use std::cell::RefCell;
use std::collections::BTreeMap;
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use syscall::data::{Map, Stat, StatVfs, TimeSpec};
use syscall::error::{Error, Result, EACCES, EEXIST, EISDIR, ENOTDIR, ENOTEMPTY, EPERM, ENOENT, EBADF, ELOOP, EINVAL};
use syscall::flag::{O_APPEND, O_CREAT, O_DIRECTORY, O_STAT, O_EXCL, O_TRUNC, O_ACCMODE, O_RDONLY, O_WRONLY, O_RDWR, MODE_PERM, O_SYMLINK, O_NOFOLLOW};
use syscall::scheme::Scheme;

use BLOCK_SIZE;
use disk::Disk;
use filesystem::FileSystem;
use node::Node;

use super::resource::{Resource, DirResource, FileResource};

pub struct FileScheme<D: Disk> {
    name: String,
    fs: RefCell<FileSystem<D>>,
    next_id: AtomicUsize,
    files: RefCell<BTreeMap<usize, Box<Resource<D>>>>,
    fmap: RefCell<BTreeMap<usize, usize>>,
}

impl<D: Disk> FileScheme<D> {
    pub fn new(name: String, fs: FileSystem<D>) -> FileScheme<D> {
        FileScheme {
            name: name,
            fs: RefCell::new(fs),
            next_id: AtomicUsize::new(1),
            files: RefCell::new(BTreeMap::new()),
            fmap: RefCell::new(BTreeMap::new()),
        }
    }

    fn resolve_symlink(&self, fs: &mut FileSystem<D>, uid: u32, gid: u32, url: &[u8], node: (u64, Node), nodes: &mut Vec<(u64, Node)>) -> Result<Vec<u8>> {
        let mut node = node;
        for _ in 1..10 { // XXX What should the limit be?
            let mut buf = [0; 4096];
            let count = fs.read_node(node.0, 0, &mut buf)?;
            let scheme = format!("{}:", &self.name);
            let canon = canonicalize(&format!("{}{}", scheme, str::from_utf8(url).unwrap()).as_bytes(), &buf[0..count]);
            let path = str::from_utf8(&canon[scheme.len()..]).unwrap_or("").trim_matches('/');
            nodes.clear();
            if let Some(next_node) = self.path_nodes(fs, path, uid, gid, nodes)? {
                if !next_node.1.is_symlink() {
                    if canon.starts_with(scheme.as_bytes()) {
                        nodes.push(next_node);
                        return Ok(canon[scheme.len()..].to_vec());
                    } else {
                        // TODO: Find way to support symlink to another scheme
                        return Err(Error::new(ENOENT));
                    }
                }
                node = next_node;
            } else {
                return Err(Error::new(ENOENT));
            }
        }
        Err(Error::new(ELOOP))
    }

    fn path_nodes(&self, fs: &mut FileSystem<D>, path: &str, uid: u32, gid: u32, nodes: &mut Vec<(u64, Node)>) -> Result<Option<(u64, Node)>> {
        let mut parts = path.split('/').filter(|part| ! part.is_empty());
        let mut part_opt = None;
        let mut block = fs.header.1.root;
        loop {
            let node_res = match part_opt {
                None => fs.node(block),
                Some(part) => fs.find_node(part, block),
            };

            part_opt = parts.next();
            if part_opt.is_some() {
                let node = node_res?;
                if ! node.1.permission(uid, gid, Node::MODE_EXEC) {
                    return Err(Error::new(EACCES));
                }
                if node.1.is_symlink() {
                    let mut url = Vec::new();
                    url.extend_from_slice(self.name.as_bytes());
                    url.push(b':');
                    for i in nodes.iter() {
                        url.push(b'/');
                        url.extend_from_slice(&i.1.name);
                    }
                    self.resolve_symlink(fs, uid, gid, &url, node, nodes)?;
                    block = nodes.last().unwrap().0;
                } else if ! node.1.is_dir() {
                    return Err(Error::new(ENOTDIR));
                } else {
                    block = node.0;
                    nodes.push(node);
                }
            } else {
                match node_res {
                    Ok(node) => return Ok(Some(node)),
                    Err(err) => match err.errno {
                        ENOENT => return Ok(None),
                        _ => return Err(err)
                    }
                }
            }
        }
    }
}

/// Make a relative path absolute
/// Given a cwd of "scheme:/path"
/// This function will turn "foo" into "scheme:/path/foo"
/// "/foo" will turn into "scheme:/foo"
/// "bar:/foo" will be used directly, as it is already absolute
pub fn canonicalize(current: &[u8], path: &[u8]) -> Vec<u8> {
    // This function is modified from a version in the kernel
    let mut canon = if path.iter().position(|&b| b == b':').is_none() {
        let cwd = &current[0..current.iter().rposition(|x| *x == '/' as u8).unwrap_or(0)];

        let mut canon = if !path.starts_with(b"/") {
            let mut c = cwd.to_vec();
            if ! c.ends_with(b"/") {
                c.push(b'/');
            }
            c
        } else {
            cwd[..cwd.iter().position(|&b| b == b':').map_or(1, |i| i + 1)].to_vec()
        };

        canon.extend_from_slice(&path);
        canon
    } else {
        path.to_vec()
    };

    // NOTE: assumes the scheme does not include anything like "../" or "./"
    let mut result = {
        let parts = canon.split(|&c| c == b'/')
            .filter(|&part| part != b".")
            .rev()
            .scan(0, |nskip, part| {
                if part == b"." {
                    Some(None)
                } else if part == b".." {
                    *nskip += 1;
                    Some(None)
                } else {
                    if *nskip > 0 {
                        *nskip -= 1;
                        Some(None)
                    } else {
                        Some(Some(part))
                    }
                }
            })
            .filter_map(|x| x)
            .collect::<Vec<_>>();
        parts
            .iter()
            .rev()
            .fold(Vec::new(), |mut vec, &part| {
                vec.extend_from_slice(part);
                vec.push(b'/');
                vec
            })
    };
    result.pop(); // remove extra '/'

    // replace with the root of the scheme if it's empty
    if result.len() == 0 {
        let pos = canon.iter()
                        .position(|&b| b == b':')
                        .map_or(canon.len(), |p| p + 1);
        canon.truncate(pos);
        canon
    } else {
        result
    }
}

impl<D: Disk> Scheme for FileScheme<D> {
    fn open(&self, url: &[u8], flags: usize, uid: u32, gid: u32) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        // println!("Open '{}' {:X}", path, flags);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        let node_opt = self.path_nodes(&mut fs, path, uid, gid, &mut nodes)?;
        let resource: Box<Resource<D>> = match node_opt {
            Some(node) => if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
                return Err(Error::new(EEXIST));
            } else if node.1.is_dir() {
                if flags & O_ACCMODE == O_RDONLY {
                    if ! node.1.permission(uid, gid, Node::MODE_READ) {
                        // println!("dir not readable {:o}", node.1.mode);
                        return Err(Error::new(EACCES));
                    }

                    let mut children = Vec::new();
                    fs.child_nodes(&mut children, node.0)?;

                    let mut data = Vec::new();
                    for child in children.iter() {
                        if let Ok(name) = child.1.name() {
                            if ! data.is_empty() {
                                data.push(b'\n');
                            }
                            data.extend_from_slice(&name.as_bytes());
                        }
                    }

                    Box::new(DirResource::new(path.to_string(), node.0, Some(data), uid))
                } else if flags & O_WRONLY == O_WRONLY {
                    // println!("{:X} & {:X}: EISDIR {}", flags, O_DIRECTORY, path);
                    return Err(Error::new(EISDIR));
                } else {
                    Box::new(DirResource::new(path.to_string(), node.0, None, uid))
                }
            } else if node.1.is_symlink() && !(flags & O_STAT == O_STAT && flags  & O_NOFOLLOW == O_NOFOLLOW) && flags & O_SYMLINK != O_SYMLINK {
                let mut resolve_nodes = Vec::new();
                let resolved = self.resolve_symlink(&mut fs, uid, gid, url, node, &mut resolve_nodes)?;
                drop(fs);
                return self.open(&resolved, flags, uid, gid);
            } else if !node.1.is_symlink() && flags & O_SYMLINK == O_SYMLINK {
                  return Err(Error::new(EINVAL));
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

                    fs.node_set_len(node.0, 0)?;
                }

                let seek = if flags & O_APPEND == O_APPEND {
                    fs.node_len(node.0)?
                } else {
                    0
                };

                Box::new(FileResource::new(path.to_string(), node.0, flags, seek, uid))
            },
            None => if flags & O_CREAT == O_CREAT {
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
                        let mode_type = if dir {
                            Node::MODE_DIR
                        } else if flags & O_SYMLINK == O_SYMLINK {
                            Node::MODE_SYMLINK
                        } else {
                            Node::MODE_FILE
                        };

                        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                        let mut node = fs.create_node(mode_type | (flags as u16 & Node::MODE_PERM), &last_part, parent.0, ctime.as_secs(), ctime.subsec_nanos())?;
                        node.1.uid = uid;
                        node.1.gid = gid;
                        fs.write_at(node.0, &node.1)?;

                        if dir {
                            Box::new(DirResource::new(path.to_string(), node.0, None, uid))
                        } else {
                            let seek = if flags & O_APPEND == O_APPEND {
                                fs.node_len(node.0)?
                            } else {
                                0
                            };

                            Box::new(FileResource::new(path.to_string(), node.0, flags, seek, uid))
                        }
                    } else {
                        return Err(Error::new(EPERM));
                    }
                } else {
                    return Err(Error::new(EPERM));
                }
            } else {
                return Err(Error::new(ENOENT));
            }
        };

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.files.borrow_mut().insert(id, resource);

        Ok(id)
    }

    fn chmod(&self, url: &[u8], mode: u16, uid: u32, gid: u32) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        // println!("Chmod '{}'", path);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        if let Some(mut node) = self.path_nodes(&mut fs, path, uid, gid, &mut nodes)? {
            if node.1.uid == uid || uid == 0 {
                node.1.mode = (node.1.mode & ! MODE_PERM) | (mode & MODE_PERM);
                fs.write_at(node.0, &node.1)?;
                Ok(0)
            } else {
                Err(Error::new(EPERM))
            }
        } else {
            Err(Error::new(ENOENT))
        }
    }

    fn rmdir(&self, url: &[u8], uid: u32, gid: u32) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        // println!("Rmdir '{}'", path);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        if let Some(child) = self.path_nodes(&mut fs, path, uid, gid, &mut nodes)? {
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
        } else {
            Err(Error::new(ENOENT))
        }
    }

    fn unlink(&self, url: &[u8], uid: u32, gid: u32) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        // println!("Unlink '{}'", path);

        let mut fs = self.fs.borrow_mut();

        let mut nodes = Vec::new();
        if let Some(child) = self.path_nodes(&mut fs, path, uid, gid, &mut nodes)? {
            if let Some(parent) = nodes.last() {
                if ! parent.1.permission(uid, gid, Node::MODE_WRITE) {
                    // println!("dir not writable {:o}", parent.1.mode);
                    return Err(Error::new(EACCES));
                }

                if ! child.1.is_dir() {
                    if child.1.uid != uid {
                        // println!("file not owned by current user {}", parent.1.uid);
                        return Err(Error::new(EACCES));
                    }

                    if let Ok(child_name) = child.1.name() {
                        if child.1.is_symlink() {
                            fs.remove_node(Node::MODE_SYMLINK, child_name, parent.0).and(Ok(0))
                        } else {
                            fs.remove_node(Node::MODE_FILE, child_name, parent.0).and(Ok(0))
                        }
                    } else {
                        Err(Error::new(ENOENT))
                    }
                } else {
                    Err(Error::new(EISDIR))
                }
            } else {
                Err(Error::new(EPERM))
            }
        } else {
            Err(Error::new(ENOENT))
        }
    }

    /* Resource operations */
    #[allow(unused_variables)]
    fn dup(&self, old_id: usize, buf: &[u8]) -> Result<usize> {
        // println!("Dup {}", old_id);

        if ! buf.is_empty() {
            return Err(Error::new(EINVAL));
        }

        let mut files = self.files.borrow_mut();
        let resource = if let Some(old_resource) = files.get(&old_id) {
            old_resource.dup()?
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
        let mut files = self.files.borrow_mut();
        if let Some(file) = files.get_mut(&id) {
            file.read(buf, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn write(&self, id: usize, buf: &[u8]) -> Result<usize> {
        // println!("Write {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let mut files = self.files.borrow_mut();
        if let Some(file) = files.get_mut(&id) {
            file.write(buf, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn seek(&self, id: usize, pos: usize, whence: usize) -> Result<usize> {
        // println!("Seek {}, {} {}", id, pos, whence);
        let mut files = self.files.borrow_mut();
        if let Some(file) = files.get_mut(&id) {
            file.seek(pos, whence, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fchmod(&self, id: usize, mode: u16) -> Result<usize> {
        let mut files = self.files.borrow_mut();
        if let Some(file) = files.get_mut(&id) {
            file.fchmod(mode, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fchown(&self, id: usize, uid: u32, gid: u32) -> Result<usize> {
        let mut files = self.files.borrow_mut();
        if let Some(file) = files.get_mut(&id) {
            file.fchown(uid, gid, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fcntl(&self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        let mut files = self.files.borrow_mut();
        if let Some(file) = files.get_mut(&id) {
            file.fcntl(cmd, arg)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fevent(&self, id: usize, flags: usize) -> Result<usize> {
        let files = self.files.borrow_mut();
        if let Some(file) = files.get(&id) {
            // EPERM is returned for files that are always readable or writable
            Err(Error::new(EPERM))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        // println!("Fpath {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let files = self.files.borrow_mut();
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

    fn frename(&self, id: usize, url: &[u8], uid: u32, gid: u32) -> Result<usize> {
        let path = str::from_utf8(url).unwrap_or("").trim_matches('/');

        // println!("Frename {}, {} from {}, {}", id, path, uid, gid);

        let files = self.files.borrow_mut();
        if let Some(file) = files.get(&id) {
            //TODO: Check for EINVAL
            // The new pathname contained a path prefix of the old, or, more generally,
            // an attempt was made to make a directory a subdirectory of itself.

            let mut last_part = String::new();
            for part in path.split('/') {
                if ! part.is_empty() {
                    last_part = part.to_string();
                }
            }
            if last_part.is_empty() {
                return Err(Error::new(EPERM));
            }

            let mut fs = self.fs.borrow_mut();

            let mut orig = fs.node(file.block())?;

            if ! orig.1.owner(uid) {
                // println!("orig not owned by caller {}", uid);
                return Err(Error::new(EACCES));
            }

            let mut nodes = Vec::new();
            let node_opt = self.path_nodes(&mut fs, path, uid, gid, &mut nodes)?;

            if let Some(parent) = nodes.last() {
                if ! parent.1.owner(uid) {
                    // println!("parent not owned by caller {}", uid);
                    return Err(Error::new(EACCES));
                }

                if let Some(ref node) = node_opt {
                    if ! node.1.owner(uid) {
                        // println!("new dir not owned by caller {}", uid);
                        return Err(Error::new(EACCES));
                    }

                    if node.1.is_dir() {
                        if ! orig.1.is_dir() {
                            // println!("orig is file, new is dir");
                            return Err(Error::new(EACCES));
                        }

                        let mut children = Vec::new();
                        fs.child_nodes(&mut children, node.0)?;

                        if ! children.is_empty() {
                            // println!("new dir not empty");
                            return Err(Error::new(ENOTEMPTY));
                        }
                    } else {
                        if orig.1.is_dir() {
                            // println!("orig is dir, new is file");
                            return Err(Error::new(ENOTDIR));
                        }
                    }
                }

                let orig_parent = orig.1.parent;

                orig.1.set_name(&last_part)?;
                orig.1.parent = parent.0;

                if parent.0 != orig_parent {
                    fs.remove_blocks(orig.0, 1, orig_parent)?;
                }

                fs.write_at(orig.0, &orig.1)?;

                if let Some(node) = node_opt {
                    if node.0 != orig.0 {
                        fs.node_set_len(node.0, 0)?;
                        fs.remove_blocks(node.0, 1, parent.0)?;
                        fs.write_at(node.0, &Node::default())?;
                        fs.deallocate(node.0, BLOCK_SIZE)?;
                    }
                }

                if parent.0 != orig_parent {
                    fs.insert_blocks(orig.0, BLOCK_SIZE, parent.0)?;
                }

                Ok(0)
            } else {
                Err(Error::new(EPERM))
            }
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        // println!("Fstat {}, {:X}", id, stat as *mut Stat as usize);
        let files = self.files.borrow_mut();
        if let Some(file) = files.get(&id) {
            file.stat(stat, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fstatvfs(&self, id: usize, stat: &mut StatVfs) -> Result<usize> {
        let files = self.files.borrow_mut();
        if let Some(_file) = files.get(&id) {
            let mut fs = self.fs.borrow_mut();

            let free = fs.header.1.free;
            let free_size = fs.node_len(free)?;

            stat.f_bsize = BLOCK_SIZE as u32;
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
        let mut files = self.files.borrow_mut();
        if let Some(file) = files.get_mut(&id) {
            file.sync(&mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn ftruncate(&self, id: usize, len: usize) -> Result<usize> {
        // println!("Ftruncate {}, {}", id, len);
        let mut files = self.files.borrow_mut();
        if let Some(file) = files.get_mut(&id) {
            file.truncate(len, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn futimens(&self, id: usize, times: &[TimeSpec]) -> Result<usize> {
        // println!("Futimens {}, {}", id, times.len());
        let mut files = self.files.borrow_mut();
        if let Some(file) = files.get_mut(&id) {
            file.utimens(times, &mut self.fs.borrow_mut())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fmap(&self, id: usize, map: &Map) -> Result<usize> {
        // println!("Fmap {}, {:?}", id, map);
        let mut files = self.files.borrow_mut();
        if let Some(file) = files.get_mut(&id) {
            let address = file.fmap(map, &mut self.fs.borrow_mut())?;
            self.fmap.borrow_mut().insert(address, id);
            Ok(address)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn funmap(&self, address: usize) -> Result<usize> {
        if let Some(id) = self.fmap.borrow_mut().remove(&address) {
            let mut files = self.files.borrow_mut();
            if let Some(file) = files.get_mut(&id) {
                file.funmap(address, &mut self.fs.borrow_mut())
            } else {
                Err(Error::new(EINVAL))
            }
        } else {
            Err(Error::new(EINVAL))
        }
    }

    fn close(&self, id: usize) -> Result<usize> {
        // println!("Close {}", id);
        let mut files = self.files.borrow_mut();
        if files.remove(&id).is_some() {
            Ok(0)
        } else {
            Err(Error::new(EBADF))
        }
    }
}
