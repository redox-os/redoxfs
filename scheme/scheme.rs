use resource::{Resource, DirResource, FileResource};

use redoxfs::{FileSystem, Node};
use spin::Mutex;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering};

use syscall::data::{Stat, StatVfs};
use syscall::error::{Error, Result, EACCES, EEXIST, EISDIR, ENOTDIR, EPERM, ENOENT, EBADF};
use syscall::flag::{O_CREAT, O_DIRECTORY, O_STAT, O_EXCL, O_TRUNC, O_ACCMODE, O_RDONLY, O_WRONLY, O_RDWR, MODE_PERM};
use syscall::scheme::Scheme;

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
}

impl Scheme for FileScheme {
    fn open(&self, url: &[u8], flags: usize, uid: u32, gid: u32) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        //println!("Open '{}' {:X}", path, flags);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        let node_result = fs.path_nodes(path, &mut nodes);
        for node in nodes.iter() {
            if ! node.1.permission(uid, gid, Node::MODE_EXEC) {
                // println!("dir not executable {:o}", node.1.mode);
                return Err(Error::new(EACCES));
            }
            if ! node.1.is_dir() {
                return Err(Error::new(ENOTDIR));
            }
        }

        let resource: Box<Resource> = match node_result {
            Ok(node) => if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
                return Err(Error::new(EEXIST));
            } else if node.1.is_dir() {
                if flags & O_STAT != O_STAT && flags & O_DIRECTORY != O_DIRECTORY {
                    // println!("{:X} & {:X}: EISDIR {}", flags, O_DIRECTORY, path);
                    return Err(Error::new(EISDIR));
                }

                if flags & O_ACCMODE == O_RDONLY {
                    if ! node.1.permission(uid, gid, Node::MODE_READ) {
                        // println!("dir not readable {:o}", node.1.mode);
                        return Err(Error::new(EACCES));
                    }

                    let mut children = Vec::new();
                    try!(fs.child_nodes(&mut children, node.0));

                    let mut data = Vec::new();
                    for child in children.iter() {
                        if let Ok(name) = child.1.name() {
                            if ! data.is_empty() {
                                data.push(b'\n');
                            }
                            data.extend_from_slice(&name.as_bytes());
                        }
                    }

                    Box::new(DirResource::new(path.to_string(), node.0, data))
                } else if flags & O_STAT == O_STAT {
                    Box::new(DirResource::new(path.to_string(), node.0, Vec::new()))
                } else {
                    // println!("dir not opened with O_RDONLY");
                    return Err(Error::new(EACCES));
                }
            } else {
                if flags & O_DIRECTORY == O_DIRECTORY {
                    // println!("{:X} & {:X}: ENOTDIR {}", flags, O_DIRECTORY, path);
                    return Err(Error::new(ENOTDIR));
                }

                if (flags & O_ACCMODE == O_RDONLY || flags & O_ACCMODE == O_RDWR) && ! node.1.permission(uid, gid, Node::MODE_READ) {
                    // println!("file not readable {:o}", node.1.mode);
                    return Err(Error::new(EACCES));
                }

                if (flags & O_ACCMODE == O_WRONLY || flags & O_ACCMODE == O_RDWR) && ! node.1.permission(uid, gid, Node::MODE_WRITE) {
                    // println!("file not writable {:o}", node.1.mode);
                    return Err(Error::new(EACCES));
                }

                if flags & O_TRUNC == O_TRUNC {
                    if ! node.1.permission(uid, gid, Node::MODE_WRITE) {
                        // println!("file not writable {:o}", node.1.mode);
                        return Err(Error::new(EACCES));
                    }

                    try!(fs.node_set_len(node.0, 0));
                }

                Box::new(FileResource::new(path.to_string(), node.0, flags))
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
                        if ! parent.1.permission(uid, gid, Node::MODE_WRITE) {
                            // println!("dir not writable {:o}", parent.1.mode);
                            return Err(Error::new(EACCES));
                        }

                        let dir = flags & O_DIRECTORY == O_DIRECTORY;

                        let mut node = try!(fs.create_node(if dir { Node::MODE_DIR } else { Node::MODE_FILE } | (flags as u16 & Node::MODE_PERM), &last_part, parent.0));
                        node.1.uid = uid;
                        node.1.gid = gid;
                        try!(fs.write_at(node.0, &node.1));

                        if (flags & O_ACCMODE == O_RDONLY || flags & O_ACCMODE == O_RDWR) && ! node.1.permission(uid, gid, Node::MODE_READ) {
                            // println!("file not readable {:o}", node.1.mode);
                            return Err(Error::new(EACCES));
                        }

                        if (flags & O_ACCMODE == O_WRONLY || flags & O_ACCMODE == O_RDWR) && ! node.1.permission(uid, gid, Node::MODE_WRITE) {
                            // println!("file not writable {:o}", node.1.mode);
                            return Err(Error::new(EACCES));
                        }

                        if dir {
                            Box::new(DirResource::new(path.to_string(), node.0, Vec::new()))
                        } else {
                            Box::new(FileResource::new(path.to_string(), node.0, flags))
                        }
                    } else {
                        return Err(Error::new(EPERM));
                    }
                } else {
                    return Err(Error::new(EPERM));
                }
            } else {
                return Err(err);
            }
        };

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.files.lock().insert(id, resource);

        Ok(id)
    }

    fn chmod(&self, url: &[u8], mode: u16, uid: u32, gid: u32) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        // println!("Chmod '{}'", path);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        let node_result = fs.path_nodes(path, &mut nodes);
        for node in nodes.iter() {
            if ! node.1.permission(uid, gid, Node::MODE_EXEC) {
                // println!("dir not executable {:o}", node.1.mode);
                return Err(Error::new(EACCES));
            }
            if ! node.1.is_dir() {
                return Err(Error::new(ENOTDIR));
            }
        }

        let mut node = node_result?;
        if node.1.uid == uid || uid == 0 {
            node.1.mode = (node.1.mode & ! MODE_PERM) | (mode & MODE_PERM);
            try!(fs.write_at(node.0, &node.1));
            Ok(0)
        } else {
            Err(Error::new(EPERM))
        }
    }

    fn rmdir(&self, url: &[u8], uid: u32, gid: u32) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        // println!("Rmdir '{}'", path);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        let child = try!(fs.path_nodes(path, &mut nodes));
        for node in nodes.iter() {
            if ! node.1.permission(uid, gid, Node::MODE_EXEC) {
                // println!("dir not executable {:o}", node.1.mode);
                return Err(Error::new(EACCES));
            }
            if ! node.1.is_dir() {
                return Err(Error::new(ENOTDIR));
            }
        }

        if let Some(parent) = nodes.last() {
            if ! parent.1.permission(uid, gid, Node::MODE_WRITE) {
                // println!("dir not writable {:o}", parent.1.mode);
                return Err(Error::new(EACCES));
            }

            if child.1.is_dir() {
                if ! child.1.permission(uid, gid, Node::MODE_WRITE) {
                    // println!("dir not writable {:o}", parent.1.mode);
                    return Err(Error::new(EACCES));
                }

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

    fn unlink(&self, url: &[u8], uid: u32, gid: u32) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        // println!("Unlink '{}'", path);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        let child = try!(fs.path_nodes(path, &mut nodes));
        for node in nodes.iter() {
            if ! node.1.permission(uid, gid, Node::MODE_EXEC) {
                // println!("dir not executable {:o}", node.1.mode);
                return Err(Error::new(EACCES));
            }
            if ! node.1.is_dir() {
                return Err(Error::new(ENOTDIR));
            }
        }

        if let Some(parent) = nodes.last() {
            if ! parent.1.permission(uid, gid, Node::MODE_WRITE) {
                // println!("dir not writable {:o}", parent.1.mode);
                return Err(Error::new(EACCES));
            }

            if ! child.1.is_dir() {
                if ! child.1.permission(uid, gid, Node::MODE_WRITE) {
                    // println!("file not writable {:o}", parent.1.mode);
                    return Err(Error::new(EACCES));
                }

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
    fn dup(&self, old_id: usize, buf: &[u8]) -> Result<usize> {
        // println!("Dup {}", old_id);

        let mut files = self.files.lock();
        let resource = if let Some(old_resource) = files.get(&old_id) {
            old_resource.dup(buf)?
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
            file.seek(pos, whence, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let mut files = self.files.lock();
        if let Some(mut file) = files.get_mut(&id) {
            file.fcntl(cmd, arg)
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
            if i < buf.len() {
                buf[i] = b'/';
                i += 1;
            }

            file.path(&mut buf[i..]).map(|count| i + count)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        // println!("Fstat {}, {:X}", id, stat as *mut Stat as usize);
        let files = self.files.lock();
        if let Some(file) = files.get(&id) {
            file.stat(stat, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fstatvfs(&self, id: usize, stat: &mut StatVfs) -> Result<usize> {
        let files = self.files.lock();
        if let Some(_file) = files.get(&id) {
            let mut fs = self.fs.borrow_mut();

            let free = fs.header.1.free;
            let free_size = fs.node_len(free)?;

            stat.f_bsize = 512;
            stat.f_blocks = fs.header.1.size/(stat.f_bsize as u64);
            stat.f_bfree = free_size/(stat.f_bsize as u64);
            stat.f_bavail = stat.f_bfree;

            Ok(0)
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
