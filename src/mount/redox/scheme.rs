use std::collections::BTreeMap;
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use syscall::data::{Map, Stat, StatVfs, TimeSpec};
use syscall::error::{
    Error, Result, EACCES, EBADF, EEXIST, EINVAL, EISDIR, ELOOP, ENOENT, ENOSYS, ENOTDIR,
    ENOTEMPTY, EPERM, EXDEV,
};
use syscall::flag::{
    EventFlags, MODE_PERM, O_ACCMODE, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_RDONLY, O_RDWR,
    O_STAT, O_SYMLINK, O_TRUNC, O_WRONLY,
};
use syscall::scheme::SchemeMut;

use crate::{Disk, FileSystem, Node, Transaction, TreeData, TreePtr, BLOCK_SIZE};

use super::resource::{DirResource, FileResource, Resource};

pub struct FileScheme<D: Disk> {
    name: String,
    fs: FileSystem<D>,
    next_id: AtomicUsize,
    files: BTreeMap<usize, Box<dyn Resource<D>>>,
    fmap: BTreeMap<usize, usize>,
}

impl<D: Disk> FileScheme<D> {
    pub fn new(name: String, fs: FileSystem<D>) -> FileScheme<D> {
        FileScheme {
            name: name,
            fs: fs,
            next_id: AtomicUsize::new(1),
            files: BTreeMap::new(),
            fmap: BTreeMap::new(),
        }
    }

    fn resolve_symlink(
        scheme_name: &str,
        tx: &mut Transaction<D>,
        uid: u32,
        gid: u32,
        url: &str,
        node: TreeData<Node>,
        nodes: &mut Vec<(TreeData<Node>, String)>,
    ) -> Result<Vec<u8>> {
        let atime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let mut node = node;
        for _ in 0..32 {
            // XXX What should the limit be?
            let mut buf = [0; 4096];
            let count = tx.read_node(
                node.ptr(),
                0,
                &mut buf,
                atime.as_secs(),
                atime.subsec_nanos(),
            )?;
            let scheme = format!("{}:", scheme_name);
            let canon = canonicalize(&format!("{}{}", scheme, url).as_bytes(), &buf[0..count]);
            let path = str::from_utf8(&canon[scheme.len()..])
                .unwrap_or("")
                .trim_matches('/');
            nodes.clear();
            if let Some((next_node, next_node_name)) =
                Self::path_nodes(scheme_name, tx, path, uid, gid, nodes)?
            {
                if !next_node.data().is_symlink() {
                    if canon.starts_with(scheme.as_bytes()) {
                        nodes.push((next_node, next_node_name));
                        return Ok(canon[scheme.len()..].to_vec());
                    } else {
                        return Err(Error::new(EXDEV));
                    }
                }
                node = next_node;
            } else {
                return Err(Error::new(ENOENT));
            }
        }
        Err(Error::new(ELOOP))
    }

    fn path_nodes(
        scheme_name: &str,
        tx: &mut Transaction<D>,
        path: &str,
        uid: u32,
        gid: u32,
        nodes: &mut Vec<(TreeData<Node>, String)>,
    ) -> Result<Option<(TreeData<Node>, String)>> {
        let mut parts = path.split('/').filter(|part| !part.is_empty());
        let mut part_opt: Option<&str> = None;
        let mut node_ptr = TreePtr::root();
        let mut node_name = String::new();
        loop {
            let node_res = match part_opt {
                None => tx.read_tree(node_ptr),
                Some(part) => {
                    node_name = part.to_string();
                    tx.find_node(node_ptr, part)
                }
            };

            part_opt = parts.next();
            if let Some(part) = part_opt {
                let node = node_res?;
                if !node.data().permission(uid, gid, Node::MODE_EXEC) {
                    return Err(Error::new(EACCES));
                }
                if node.data().is_symlink() {
                    let mut url = String::new();
                    url.push_str(scheme_name);
                    url.push(':');
                    for (_parent, parent_name) in nodes.iter() {
                        url.push('/');
                        url.push_str(&parent_name);
                    }
                    Self::resolve_symlink(scheme_name, tx, uid, gid, &url, node, nodes)?;
                    node_ptr = nodes.last().unwrap().0.ptr();
                } else if !node.data().is_dir() {
                    return Err(Error::new(ENOTDIR));
                } else {
                    node_ptr = node.ptr();
                    nodes.push((node, part.to_string()));
                }
            } else {
                match node_res {
                    Ok(node) => return Ok(Some((node, node_name))),
                    Err(err) => match err.errno {
                        ENOENT => return Ok(None),
                        _ => return Err(err),
                    },
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
            if !c.ends_with(b"/") {
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
        let parts = canon
            .split(|&c| c == b'/')
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
        parts.iter().rev().fold(Vec::new(), |mut vec, &part| {
            vec.extend_from_slice(part);
            vec.push(b'/');
            vec
        })
    };
    result.pop(); // remove extra '/'

    // replace with the root of the scheme if it's empty
    if result.len() == 0 {
        let pos = canon
            .iter()
            .position(|&b| b == b':')
            .map_or(canon.len(), |p| p + 1);
        canon.truncate(pos);
        canon
    } else {
        result
    }
}

impl<D: Disk> SchemeMut for FileScheme<D> {
    fn open(&mut self, url: &str, flags: usize, uid: u32, gid: u32) -> Result<usize> {
        let path = url.trim_matches('/');

        // println!("Open '{}' {:X}", path, flags);

        //TODO: try to move things into one transaction
        let scheme_name = &self.name;
        let mut nodes = Vec::new();
        let node_opt = self
            .fs
            .tx(|tx| Self::path_nodes(scheme_name, tx, path, uid, gid, &mut nodes))?;
        let resource: Box<dyn Resource<D>> = match node_opt {
            Some((node, _node_name)) => {
                if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
                    return Err(Error::new(EEXIST));
                } else if node.data().is_dir() {
                    if flags & O_ACCMODE == O_RDONLY {
                        if !node.data().permission(uid, gid, Node::MODE_READ) {
                            // println!("dir not readable {:o}", node.data().mode);
                            return Err(Error::new(EACCES));
                        }

                        let mut children = Vec::new();
                        self.fs.tx(|tx| tx.child_nodes(node.ptr(), &mut children))?;

                        let mut data = Vec::new();
                        for child in children.iter() {
                            if let Some(child_name) = child.name() {
                                if !data.is_empty() {
                                    data.push(b'\n');
                                }
                                data.extend_from_slice(&child_name.as_bytes());
                            }
                        }

                        Box::new(DirResource::new(
                            path.to_string(),
                            node.ptr(),
                            Some(data),
                            uid,
                        ))
                    } else if flags & O_WRONLY == O_WRONLY {
                        // println!("{:X} & {:X}: EISDIR {}", flags, O_DIRECTORY, path);
                        return Err(Error::new(EISDIR));
                    } else {
                        Box::new(DirResource::new(path.to_string(), node.ptr(), None, uid))
                    }
                } else if node.data().is_symlink()
                    && !(flags & O_STAT == O_STAT && flags & O_NOFOLLOW == O_NOFOLLOW)
                    && flags & O_SYMLINK != O_SYMLINK
                {
                    let mut resolve_nodes = Vec::new();
                    let resolved = self.fs.tx(|tx| {
                        Self::resolve_symlink(
                            scheme_name,
                            tx,
                            uid,
                            gid,
                            url,
                            node,
                            &mut resolve_nodes,
                        )
                    })?;
                    let resolved_utf8 =
                        str::from_utf8(&resolved).map_err(|_| Error::new(EINVAL))?;
                    return self.open(resolved_utf8, flags, uid, gid);
                } else if !node.data().is_symlink() && flags & O_SYMLINK == O_SYMLINK {
                    return Err(Error::new(EINVAL));
                } else {
                    let node_ptr = node.ptr();

                    if flags & O_DIRECTORY == O_DIRECTORY {
                        // println!("{:X} & {:X}: ENOTDIR {}", flags, O_DIRECTORY, path);
                        return Err(Error::new(ENOTDIR));
                    }

                    if (flags & O_ACCMODE == O_RDONLY || flags & O_ACCMODE == O_RDWR)
                        && !node.data().permission(uid, gid, Node::MODE_READ)
                    {
                        // println!("file not readable {:o}", node.data().mode);
                        return Err(Error::new(EACCES));
                    }

                    if (flags & O_ACCMODE == O_WRONLY || flags & O_ACCMODE == O_RDWR)
                        && !node.data().permission(uid, gid, Node::MODE_WRITE)
                    {
                        // println!("file not writable {:o}", node.data().mode);
                        return Err(Error::new(EACCES));
                    }

                    if flags & O_TRUNC == O_TRUNC {
                        if !node.data().permission(uid, gid, Node::MODE_WRITE) {
                            // println!("file not writable {:o}", node.data().mode);
                            return Err(Error::new(EACCES));
                        }

                        let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                        self.fs.tx(|tx| {
                            tx.truncate_node(node_ptr, 0, mtime.as_secs(), mtime.subsec_nanos())
                        })?;
                    }

                    Box::new(FileResource::new(path.to_string(), node_ptr, flags, uid))
                }
            }
            None => {
                if flags & O_CREAT == O_CREAT {
                    let mut last_part = String::new();
                    for part in path.split('/') {
                        if !part.is_empty() {
                            last_part = part.to_string();
                        }
                    }
                    if !last_part.is_empty() {
                        if let Some((parent, _parent_name)) = nodes.last() {
                            if !parent.data().permission(uid, gid, Node::MODE_WRITE) {
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

                            let node_ptr = self.fs.tx(|tx| {
                                let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                                let mut node = tx.create_node(
                                    parent.ptr(),
                                    &last_part,
                                    mode_type | (flags as u16 & Node::MODE_PERM),
                                    ctime.as_secs(),
                                    ctime.subsec_nanos(),
                                )?;
                                let node_ptr = node.ptr();
                                if node.data().uid() != uid || node.data().gid() != gid {
                                    node.data_mut().set_uid(uid);
                                    node.data_mut().set_gid(gid);
                                    tx.sync_tree(node)?;
                                }
                                Ok(node_ptr)
                            })?;

                            if dir {
                                Box::new(DirResource::new(path.to_string(), node_ptr, None, uid))
                            } else {
                                Box::new(FileResource::new(path.to_string(), node_ptr, flags, uid))
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
            }
        };

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.files.insert(id, resource);

        Ok(id)
    }

    fn chmod(&mut self, url: &str, mode: u16, uid: u32, gid: u32) -> Result<usize> {
        let path = url.trim_matches('/');

        // println!("Chmod '{}'", path);

        let scheme_name = &self.name;
        self.fs.tx(|tx| {
            let mut nodes = Vec::new();
            if let Some((mut node, _node_name)) =
                Self::path_nodes(scheme_name, tx, path, uid, gid, &mut nodes)?
            {
                if node.data().uid() == uid || uid == 0 {
                    let old_mode = node.data().mode();
                    let new_mode = (old_mode & !MODE_PERM) | (mode & MODE_PERM);
                    if old_mode != new_mode {
                        node.data_mut().set_mode(new_mode);
                        tx.sync_tree(node)?;
                    }

                    Ok(0)
                } else {
                    Err(Error::new(EPERM))
                }
            } else {
                Err(Error::new(ENOENT))
            }
        })
    }

    fn rmdir(&mut self, url: &str, uid: u32, gid: u32) -> Result<usize> {
        let path = url.trim_matches('/');

        // println!("Rmdir '{}'", path);

        let scheme_name = &self.name;
        self.fs.tx(|tx| {
            let mut nodes = Vec::new();
            if let Some((child, child_name)) =
                Self::path_nodes(scheme_name, tx, path, uid, gid, &mut nodes)?
            {
                if let Some((parent, _parent_name)) = nodes.last() {
                    if !parent.data().permission(uid, gid, Node::MODE_WRITE) {
                        // println!("dir not writable {:o}", parent.1.mode);
                        return Err(Error::new(EACCES));
                    }

                    if child.data().is_dir() {
                        if !child.data().permission(uid, gid, Node::MODE_WRITE) {
                            // println!("dir not writable {:o}", parent.1.mode);
                            return Err(Error::new(EACCES));
                        }

                        tx.remove_node(parent.ptr(), &child_name, Node::MODE_DIR)
                            .and(Ok(0))
                    } else {
                        Err(Error::new(ENOTDIR))
                    }
                } else {
                    Err(Error::new(EPERM))
                }
            } else {
                Err(Error::new(ENOENT))
            }
        })
    }

    fn unlink(&mut self, url: &str, uid: u32, gid: u32) -> Result<usize> {
        let path = url.trim_matches('/');

        // println!("Unlink '{}'", path);

        let scheme_name = &self.name;
        self.fs.tx(|tx| {
            let mut nodes = Vec::new();
            if let Some((child, child_name)) =
                Self::path_nodes(scheme_name, tx, path, uid, gid, &mut nodes)?
            {
                if let Some((parent, _parent_name)) = nodes.last() {
                    if !parent.data().permission(uid, gid, Node::MODE_WRITE) {
                        // println!("dir not writable {:o}", parent.1.mode);
                        return Err(Error::new(EACCES));
                    }

                    if !child.data().is_dir() {
                        if child.data().uid() != uid {
                            // println!("file not owned by current user {}", parent.1.uid);
                            return Err(Error::new(EACCES));
                        }

                        if child.data().is_symlink() {
                            tx.remove_node(parent.ptr(), &child_name, Node::MODE_SYMLINK)
                                .and(Ok(0))
                        } else {
                            tx.remove_node(parent.ptr(), &child_name, Node::MODE_FILE)
                                .and(Ok(0))
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
        })
    }

    /* Resource operations */
    #[allow(unused_variables)]
    fn dup(&mut self, old_id: usize, buf: &[u8]) -> Result<usize> {
        // println!("Dup {}", old_id);

        if !buf.is_empty() {
            return Err(Error::new(EINVAL));
        }

        let resource = if let Some(old_resource) = self.files.get(&old_id) {
            old_resource.dup()?
        } else {
            return Err(Error::new(EBADF));
        };

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.files.insert(id, resource);

        Ok(id)
    }

    #[allow(unused_variables)]
    fn read(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        // println!("Read {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        if let Some(file) = self.files.get_mut(&id) {
            self.fs.tx(|tx| file.read(buf, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn write(&mut self, id: usize, buf: &[u8]) -> Result<usize> {
        // println!("Write {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        if let Some(file) = self.files.get_mut(&id) {
            self.fs.tx(|tx| file.write(buf, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn seek(&mut self, id: usize, pos: isize, whence: usize) -> Result<isize> {
        // println!("Seek {}, {} {}", id, pos, whence);
        if let Some(file) = self.files.get_mut(&id) {
            self.fs.tx(|tx| file.seek(pos, whence, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fchmod(&mut self, id: usize, mode: u16) -> Result<usize> {
        if let Some(file) = self.files.get_mut(&id) {
            self.fs.tx(|tx| file.fchmod(mode, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fchown(&mut self, id: usize, uid: u32, gid: u32) -> Result<usize> {
        if let Some(file) = self.files.get_mut(&id) {
            self.fs.tx(|tx| file.fchown(uid, gid, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fcntl(&mut self, id: usize, cmd: usize, arg: usize) -> Result<usize> {
        if let Some(file) = self.files.get_mut(&id) {
            file.fcntl(cmd, arg)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fevent(&mut self, id: usize, _flags: EventFlags) -> Result<EventFlags> {
        if let Some(_file) = self.files.get(&id) {
            // EPERM is returned for files that are always readable or writable
            Err(Error::new(EPERM))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        // println!("Fpath {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        if let Some(file) = self.files.get(&id) {
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

            let path = file.path().as_bytes();
            let mut j = 0;
            while i < buf.len() && j < path.len() {
                buf[i] = path[j];
                i += 1;
                j += 1;
            }

            Ok(i)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn frename(&mut self, id: usize, url: &str, uid: u32, gid: u32) -> Result<usize> {
        unimplemented!();
        /*TODO: FRENAME
        let path = url.trim_matches('/');

        // println!("Frename {}, {} from {}, {}", id, path, uid, gid);

        let mut files = self.files.borrow_mut();
        if let Some(file) = files.get_mut(&id) {
            //TODO: Check for EINVAL
            // The new pathname contained a path prefix of the old, or, more generally,
            // an attempt was made to make a directory a subdirectory of itself.

            let mut last_part = String::new();
            for part in path.split('/') {
                if !part.is_empty() {
                    last_part = part.to_string();
                }
            }
            if last_part.is_empty() {
                return Err(Error::new(EPERM));
            }

            let mut fs = self.fs.borrow_mut();

            let mut orig = fs.node(file.block())?;

            if !orig.1.owner(uid) {
                // println!("orig not owned by caller {}", uid);
                return Err(Error::new(EACCES));
            }

            let mut nodes = Vec::new();
            let node_opt = self.path_nodes(&mut fs, path, uid, gid, &mut nodes)?;

            if let Some(parent) = nodes.last() {
                if !parent.1.owner(uid) {
                    // println!("parent not owned by caller {}", uid);
                    return Err(Error::new(EACCES));
                }

                if let Some(ref node) = node_opt {
                    if !node.data().owner(uid) {
                        // println!("new dir not owned by caller {}", uid);
                        return Err(Error::new(EACCES));
                    }

                    if node.data().is_dir() {
                        if !orig.1.is_dir() {
                            // println!("orig is file, new is dir");
                            return Err(Error::new(EACCES));
                        }

                        let mut children = Vec::new();
                        fs.child_nodes(node.ptr(), &mut children)?;

                        if !children.is_empty() {
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

                if parent.0 != orig_parent {
                    fs.remove_blocks(orig.0, 1, orig_parent)?;
                }

                if let Some(node) = node_opt {
                    if node.0 != orig.0 {
                        fs.node_set_len(node.0, 0)?;
                        fs.remove_blocks(node.0, 1, parent.0)?;
                        fs.write_at(node.0, &Node::default())?;
                        fs.deallocate(node.0, BLOCK_SIZE)?;
                    }
                }

                orig.1.set_name(&last_part)?;
                orig.1.parent = parent.0;
                fs.write_at(orig.0, &orig.1)?;

                if parent.0 != orig_parent {
                    fs.insert_blocks(orig.0, BLOCK_SIZE, parent.0)?;
                }

                file.set_path(path);
                Ok(0)
            } else {
                Err(Error::new(EPERM))
            }
        } else {
            Err(Error::new(EBADF))
        }
        */
    }

    fn fstat(&mut self, id: usize, stat: &mut Stat) -> Result<usize> {
        // println!("Fstat {}, {:X}", id, stat as *mut Stat as usize);
        if let Some(file) = self.files.get(&id) {
            self.fs.tx(|tx| file.stat(stat, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fstatvfs(&mut self, id: usize, stat: &mut StatVfs) -> Result<usize> {
        if let Some(_file) = self.files.get(&id) {
            stat.f_bsize = BLOCK_SIZE as u32;
            stat.f_blocks = self.fs.header.size() / (stat.f_bsize as u64);
            stat.f_bfree = self.fs.allocator().free();
            stat.f_bavail = stat.f_bfree;

            Ok(0)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fsync(&mut self, id: usize) -> Result<usize> {
        // println!("Fsync {}", id);
        if let Some(file) = self.files.get_mut(&id) {
            self.fs.tx(|tx| file.sync(tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn ftruncate(&mut self, id: usize, len: usize) -> Result<usize> {
        // println!("Ftruncate {}, {}", id, len);
        if let Some(file) = self.files.get_mut(&id) {
            self.fs.tx(|tx| file.truncate(len, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn futimens(&mut self, id: usize, times: &[TimeSpec]) -> Result<usize> {
        // println!("Futimens {}, {}", id, times.len());
        if let Some(file) = self.files.get_mut(&id) {
            self.fs.tx(|tx| file.utimens(times, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fmap(&mut self, id: usize, map: &Map) -> Result<usize> {
        // println!("Fmap {}, {:?}", id, map);
        if let Some(file) = self.files.get_mut(&id) {
            let address = self.fs.tx(|tx| file.fmap(map, tx))?;
            self.fmap.insert(address, id);
            Ok(address)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn funmap_old(&mut self, address: usize) -> Result<usize> {
        if let Some(id) = self.fmap.remove(&address) {
            if let Some(file) = self.files.get_mut(&id) {
                self.fs.tx(|tx| file.funmap(address, tx))
            } else {
                Err(Error::new(EINVAL))
            }
        } else {
            Err(Error::new(EINVAL))
        }
    }

    //TODO: implement (length is ignored!)
    fn funmap(&mut self, address: usize, length: usize) -> Result<usize> {
        println!("redoxfs: funmap 0x{:X}, {}", address, length);
        if let Some(id) = self.fmap.remove(&address) {
            if let Some(file) = self.files.get_mut(&id) {
                self.fs.tx(|tx| file.funmap(address, tx))
            } else {
                Err(Error::new(EINVAL))
            }
        } else {
            Err(Error::new(EINVAL))
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
