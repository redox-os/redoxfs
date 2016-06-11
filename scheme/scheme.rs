use resource::{Resource, DirResource, FileResource};

use redoxfs::{FileSystem, Node};

use std::collections::BTreeMap;

use system::error::{Error, Result, EEXIST, EISDIR, ENOTDIR, EPERM, ENOENT, EBADF};
use system::scheme::Scheme;
use system::syscall::{Stat, O_CREAT, O_TRUNC};

pub struct FileScheme {
    fs: FileSystem,
    next_id: isize,
    files: BTreeMap<usize, Box<Resource>>
}

impl FileScheme {
    pub fn new(fs: FileSystem) -> FileScheme {
        FileScheme {
            fs: fs,
            next_id: 1,
            files: BTreeMap::new()
        }
    }

    fn open_inner(&mut self, url: &str, flags: usize) -> Result<Box<Resource>> {
        let path = url.split(':').nth(1).unwrap_or("").trim_matches('/');

        // println!("Open '{}' {:X}", path, flags);

        let mut nodes = Vec::new();
        let node_result = self.fs.path_nodes(path, &mut nodes);

        match node_result {
            Ok(node) => if node.1.is_dir() {
                let mut data = Vec::new();
                let mut children = Vec::new();
                try!(self.fs.child_nodes(&mut children, node.0));
                for child in children.iter() {
                    if let Ok(name) = child.1.name() {
                        if ! data.is_empty() {
                            data.push(b'\n');
                        }
                        data.extend_from_slice(&name.as_bytes());
                        if child.1.is_dir() {
                            data.push(b'/');
                        }
                    }
                }
                return Ok(Box::new(DirResource::new(url, data)));
            } else {
                if flags & O_TRUNC == O_TRUNC {
                    // println!("Truncate {}", path);
                    try!(self.fs.node_set_len(node.0, 0));
                }
                let size = try!(self.fs.node_len(node.0));
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
                        let node = try!(self.fs.create_node(Node::MODE_FILE, &last_part, parent.0));
                        return Ok(Box::new(FileResource::new(url, node.0, 0)));
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
    fn open(&mut self, url: &str, flags: usize, _mode: usize) -> Result<usize> {
        let resource = try!(self.open_inner(url, flags));

        let id = self.next_id as usize;
        self.next_id += 1;
        if self.next_id < 0 {
            self.next_id = 1;
        }

        self.files.insert(id, resource);

        Ok(id)
    }

    fn mkdir(&mut self, url: &str, _mode: usize) -> Result<usize> {
        let path = url.split(':').nth(1).unwrap_or("").trim_matches('/');

        // println!("Mkdir '{}'", path);

        let mut nodes = Vec::new();
        match self.fs.path_nodes(path, &mut nodes) {
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
                        self.fs.create_node(Node::MODE_DIR, &last_part, parent.0).and(Ok(0))
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

    fn rmdir(&mut self, url: &str) -> Result<usize> {
        let path = url.split(':').nth(1).unwrap_or("").trim_matches('/');

        // println!("Rmdir '{}'", path);

        let mut nodes = Vec::new();
        let child = try!(self.fs.path_nodes(path, &mut nodes));
        if let Some(parent) = nodes.last() {
            if child.1.is_dir() {
                if let Ok(child_name) = child.1.name() {
                    self.fs.remove_node(Node::MODE_DIR, child_name, parent.0).and(Ok(0))
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

    fn stat(&mut self, url: &str, stat: &mut Stat) -> Result<usize> {
        let resource = try!(self.open_inner(url, 0));
        resource.stat(stat)
    }

    fn unlink(&mut self, url: &str) -> Result<usize> {
        let path = url.split(':').nth(1).unwrap_or("").trim_matches('/');

        // println!("Unlink '{}'", path);

        let mut nodes = Vec::new();
        let child = try!(self.fs.path_nodes(path, &mut nodes));
        if let Some(parent) = nodes.last() {
            if ! child.1.is_dir() {
                if let Ok(child_name) = child.1.name() {
                    self.fs.remove_node(Node::MODE_FILE, child_name, parent.0).and(Ok(0))
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
    fn dup(&mut self, old_id: usize) -> Result<usize> {
        // println!("Dup {}", old_id);

        let resource = try!(try!(self.files.get(&old_id).ok_or(Error::new(EBADF))).dup());

        let id = self.next_id as usize;
        self.next_id += 1;
        if self.next_id < 0 {
            self.next_id = 1;
        }

        self.files.insert(id, resource);

        Ok(id)
    }

    #[allow(unused_variables)]
    fn read(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        // println!("Read {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        if let Some(mut file) = self.files.get_mut(&id) {
            file.read(buf, &mut self.fs)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn write(&mut self, id: usize, buf: &[u8]) -> Result<usize> {
        // println!("Write {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        if let Some(mut file) = self.files.get_mut(&id) {
            file.write(buf, &mut self.fs)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn seek(&mut self, id: usize, pos: usize, whence: usize) -> Result<usize> {
        // println!("Seek {}, {} {}", id, pos, whence);
        if let Some(mut file) = self.files.get_mut(&id) {
            file.seek(pos, whence)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        // println!("Fpath {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        if let Some(file) = self.files.get(&id) {
            file.path(buf)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        // println!("Fstat {}, {:X}", id, stat as *mut Stat as usize);
        if let Some(file) = self.files.get(&id) {
            file.stat(stat)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fsync(&mut self, id: usize) -> Result<usize> {
        // println!("Fsync {}", id);
        if let Some(mut file) = self.files.get_mut(&id) {
            file.sync()
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn ftruncate(&mut self, id: usize, len: usize) -> Result<usize> {
        // println!("Ftruncate {}, {}", id, len);
        if let Some(mut file) = self.files.get_mut(&id) {
            file.truncate(len, &mut self.fs)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn close(&mut self, id: usize) -> Result<usize> {
        // println!("Close {}", id);
        if self.files.remove(&id).is_some() {
            Ok(0)
        } else {
            Err(Error::new(EBADF))
        }
    }
}
