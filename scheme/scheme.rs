use resource::{Resource, DirResource, FileResource};

use redoxfs::{FileSystem, Node};
use spin::Mutex;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering};

use syscall::error::{Error, Result, EEXIST, EISDIR, ENOTDIR, EPERM, ENOENT, EBADF};
use syscall::scheme::Scheme;
use syscall::{Stat, O_CREAT, O_TRUNC};

pub struct FileScheme {
    name: &'static str,
    fs: RefCell<FileSystem>,
    next_id: AtomicUsize,
    files: Mutex<BTreeMap<usize, Box<Resource>>>
}

impl FileScheme {
    pub fn new(name: &'static str, fs: FileSystem) -> FileScheme {
        FileScheme {
            name: name,
            fs: RefCell::new(fs),
            next_id: AtomicUsize::new(1),
            files: Mutex::new(BTreeMap::new())
        }
    }

    fn open_inner(&self, url: &[u8], flags: usize) -> Result<Box<Resource>> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        //println!("Open '{}' {:X}", path, flags);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        let node_result = fs.path_nodes(path, &mut nodes);

        match node_result {
            Ok(node) => if node.1.is_dir() {
                let mut data = Vec::new();
                let mut children = Vec::new();
                try!(fs.child_nodes(&mut children, node.0));
                for child in children.iter() {
                    if let Ok(name) = child.1.name() {
                        if ! data.is_empty() {
                            data.push(b'\n');
                        }
                        data.extend_from_slice(&name.as_bytes());
                    }
                }
                return Ok(Box::new(DirResource::new(path.as_bytes(), data)));
            } else {
                if flags & O_TRUNC == O_TRUNC {
                    // println!("Truncate {}", path);
                    try!(fs.node_set_len(node.0, 0));
                }
                let size = try!(fs.node_len(node.0));
                return Ok(Box::new(FileResource::new(url, node.0, size)));
            },
            Err(err) => if err.errno == ENOENT && flags & O_CREAT == O_CREAT {
                let mut last_part = String::new();
                for part in path.split('/') {
                    if ! part.is_empty() {
                        last_part = part.to_string();
                    }
                }
                if ! last_part.is_empty() {
                    if let Some(parent) = nodes.last() {
                        let node = try!(fs.create_node(Node::MODE_FILE, &last_part, parent.0));
                        return Ok(Box::new(FileResource::new(path.as_bytes(), node.0, 0)));
                    } else {
                        return Err(Error::new(EPERM));
                    }
                } else {
                    return Err(Error::new(EPERM));
                }
            } else {
                return Err(err);
            }
        }
    }
}

impl Scheme for FileScheme {
    fn open(&self, url: &[u8], flags: usize) -> Result<usize> {
        let resource = try!(self.open_inner(url, flags));

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.files.lock().insert(id, resource);

        Ok(id)
    }

    fn mkdir(&self, url: &[u8], _mode: usize) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        // println!("Mkdir '{}'", path);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        match fs.path_nodes(path, &mut nodes) {
            Ok(_node) => Err(Error::new(EEXIST)),
            Err(err) => if err.errno == ENOENT {
                let mut last_part = String::new();
                for part in path.split('/') {
                    if ! part.is_empty() {
                        last_part = part.to_owned();
                    }
                }
                if ! last_part.is_empty() {
                    if let Some(parent) = nodes.last() {
                        fs.create_node(Node::MODE_DIR, &last_part, parent.0).and(Ok(0))
                    } else {
                        Err(Error::new(EPERM))
                    }
                } else {
                    Err(Error::new(EPERM))
                }
            } else {
                Err(err)
            }
        }
    }

    fn rmdir(&self, url: &[u8]) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        // println!("Rmdir '{}'", path);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        let child = try!(fs.path_nodes(path, &mut nodes));
        if let Some(parent) = nodes.last() {
            if child.1.is_dir() {
                if let Ok(child_name) = child.1.name() {
                    fs.remove_node(Node::MODE_DIR, child_name, parent.0).and(Ok(0))
                } else {
                    Err(Error::new(ENOENT))
                }
            } else {
                Err(Error::new(ENOTDIR))
            }
        } else {
            Err(Error::new(EPERM))
        }
    }

    fn unlink(&self, url: &[u8]) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        // println!("Unlink '{}'", path);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        let child = try!(fs.path_nodes(path, &mut nodes));
        if let Some(parent) = nodes.last() {
            if ! child.1.is_dir() {
                if let Ok(child_name) = child.1.name() {
                    fs.remove_node(Node::MODE_FILE, child_name, parent.0).and(Ok(0))
                } else {
                    Err(Error::new(ENOENT))
                }
            } else {
                Err(Error::new(EISDIR))
            }
        } else {
            Err(Error::new(EPERM))
        }
    }

    /* Resource operations */
    #[allow(unused_variables)]
    fn dup(&self, old_id: usize) -> Result<usize> {
        // println!("Dup {}", old_id);

        let mut files = self.files.lock();
        let resource = if let Some(old_resource) = files.get(&old_id) {
            try!(old_resource.dup())
        } else {
            return Err(Error::new(EBADF));
        };

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        files.insert(id, resource);

        Ok(id)
    }

    #[allow(unused_variables)]
    fn read(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        // println!("Read {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let mut files = self.files.lock();
        if let Some(mut file) = files.get_mut(&id) {
            file.read(buf, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        // println!("Write {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let mut files = self.files.lock();
        if let Some(mut file) = files.get_mut(&id) {
            file.write(buf, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn seek(&self, id: usize, pos: usize, whence: usize) -> Result<usize> {
        // println!("Seek {}, {} {}", id, pos, whence);
        let mut files = self.files.lock();
        if let Some(mut file) = files.get_mut(&id) {
            file.seek(pos, whence)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        // println!("Fpath {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let files = self.files.lock();
        if let Some(file) = files.get(&id) {
            let name = self.name.as_bytes();
            let mut i = 0;
            while i < buf.len() && i < name.len() {
                buf[i] = name[i];
                i += 1;
            }
            if i < buf.len() {
                buf[i] = b':';
                i += 1;
            }
            match file.path(&mut buf[i..]) {
                Ok(count) => Ok(i + count),
                Err(err) => Err(err)
            }
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        // println!("Fstat {}, {:X}", id, stat as *mut Stat as usize);
        let files = self.files.lock();
        if let Some(file) = files.get(&id) {
            file.stat(stat)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fsync(&self, id: usize) -> Result<usize> {
        // println!("Fsync {}", id);
        let mut files = self.files.lock();
        if let Some(mut file) = files.get_mut(&id) {
            file.sync()
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn ftruncate(&self, id: usize, len: usize) -> Result<usize> {
        // println!("Ftruncate {}, {}", id, len);
        let mut files = self.files.lock();
        if let Some(mut file) = files.get_mut(&id) {
            file.truncate(len, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn close(&self, id: usize) -> Result<usize> {
        // println!("Close {}", id);
        let mut files = self.files.lock();
        if files.remove(&id).is_some() {
            Ok(0)
        } else {
            Err(Error::new(EBADF))
        }
    }
}
