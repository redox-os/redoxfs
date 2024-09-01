use std::collections::BTreeMap;
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use redox_scheme::{CallerCtx, OpenResult, SchemeMut};
use syscall::data::{Stat, StatVfs, TimeSpec};
use syscall::error::{
    Error, Result, EACCES, EBADF, EBUSY, EEXIST, EINVAL, EISDIR, ELOOP, ENOENT, ENOTDIR, ENOTEMPTY,
    EPERM, EXDEV,
};
use syscall::flag::{
    EventFlags, MapFlags, O_ACCMODE, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_RDONLY, O_RDWR,
    O_STAT, O_SYMLINK, O_TRUNC, O_WRONLY,
};
use syscall::schemev2::NewFdFlags;
use syscall::{MunmapFlags, EBADFD};

use redox_path::{
    canonicalize_to_standard, canonicalize_using_cwd, canonicalize_using_scheme, scheme_path,
    RedoxPath,
};

use crate::{Disk, FileSystem, Node, Transaction, TreeData, TreePtr, BLOCK_SIZE};

use super::resource::{DirResource, FileResource, Resource};

pub struct FileScheme<D: Disk> {
    name: String,
    pub(crate) fs: FileSystem<D>,
    next_id: AtomicUsize,
    files: BTreeMap<usize, Box<dyn Resource<D>>>,
    fmap: super::resource::Fmaps,
}

impl<D: Disk> FileScheme<D> {
    pub fn new(name: String, fs: FileSystem<D>) -> FileScheme<D> {
        FileScheme {
            name,
            fs,
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
        full_path: &str,
        node: TreeData<Node>,
        nodes: &mut Vec<(TreeData<Node>, String)>,
    ) -> Result<String> {
        let atime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        // symbolic link is relative to this part of the url
        let mut working_dir =
            dirname(full_path).unwrap_or(scheme_path(scheme_name).ok_or(Error::new(EINVAL))?);
        // node of the link
        let mut node = node;

        for _ in 0..32 {
            // XXX What should the limit be?
            assert!(node.data().is_symlink());
            let mut buf = [0; 4096];
            let count = tx.read_node(
                node.ptr(),
                0,
                &mut buf,
                atime.as_secs(),
                atime.subsec_nanos(),
            )?;

            let target = canonicalize_to_standard(
                Some(&working_dir),
                str::from_utf8(&buf[..count]).or(Err(Error::new(EINVAL)))?,
            )
            .ok_or(Error::new(EINVAL))?;
            let target_as_path = RedoxPath::from_absolute(&target).ok_or(Error::new(EINVAL))?;

            let (scheme, reference) = target_as_path.as_parts().ok_or(Error::new(EINVAL))?;
            if scheme.as_ref() != scheme_name {
                return Err(Error::new(EXDEV));
            }
            let target_reference = reference.to_string();

            nodes.clear();
            if let Some((next_node, next_node_name)) =
                Self::path_nodes(scheme_name, tx, &target_reference, uid, gid, nodes)?
            {
                if !next_node.data().is_symlink() {
                    nodes.push((next_node, next_node_name));
                    return Ok(target_reference);
                }
                node = next_node;
                working_dir = dirname(&target).ok_or(Error::new(EINVAL))?.to_string();
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

/// given a path with a scheme, return the containing directory (or scheme)
fn dirname(path: &str) -> Option<String> {
    canonicalize_using_cwd(Some(path), "..")
}

impl<D: Disk> SchemeMut for FileScheme<D> {
    fn xopen(&mut self, url: &str, flags: usize, ctx: &CallerCtx) -> Result<OpenResult> {
        let CallerCtx { uid, gid, .. } = *ctx;

        let path = url.trim_matches('/');

        // println!("Open '{}' {:X}", path, flags);

        //TODO: try to move things into one transaction
        let scheme_name = &self.name;
        let mut nodes = Vec::new();
        let node_opt = self
            .fs
            .tx(|tx| Self::path_nodes(scheme_name, tx, path, uid, gid, &mut nodes))?;
        let parent_ptr_opt = nodes.last().map(|x| x.0.ptr());
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
                            parent_ptr_opt,
                            node.ptr(),
                            Some(data),
                            uid,
                        ))
                    } else if flags & O_WRONLY == O_WRONLY {
                        // println!("{:X} & {:X}: EISDIR {}", flags, O_DIRECTORY, path);
                        return Err(Error::new(EISDIR));
                    } else {
                        Box::new(DirResource::new(
                            path.to_string(),
                            parent_ptr_opt,
                            node.ptr(),
                            None,
                            uid,
                        ))
                    }
                } else if node.data().is_symlink()
                    && !(flags & O_STAT == O_STAT && flags & O_NOFOLLOW == O_NOFOLLOW)
                    && flags & O_SYMLINK != O_SYMLINK
                {
                    let mut resolve_nodes = Vec::new();
                    let full_path =
                        canonicalize_using_scheme(scheme_name, url).ok_or(Error::new(EINVAL))?;
                    let resolved = self.fs.tx(|tx| {
                        Self::resolve_symlink(
                            scheme_name,
                            tx,
                            uid,
                            gid,
                            &full_path,
                            node,
                            &mut resolve_nodes,
                        )
                    })?;
                    return self.xopen(&resolved, flags, ctx);
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

                    Box::new(FileResource::new(
                        path.to_string(),
                        parent_ptr_opt,
                        node_ptr,
                        flags,
                        uid,
                    ))
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
                                Box::new(DirResource::new(
                                    path.to_string(),
                                    parent_ptr_opt,
                                    node_ptr,
                                    None,
                                    uid,
                                ))
                            } else {
                                Box::new(FileResource::new(
                                    path.to_string(),
                                    parent_ptr_opt,
                                    node_ptr,
                                    flags,
                                    uid,
                                ))
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
        self.fmap
            .entry(resource.node_ptr().id())
            .or_insert_with(Default::default)
            .open_fds += 1;

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.files.insert(id, resource);

        Ok(OpenResult::ThisScheme {
            number: id,
            flags: NewFdFlags::POSITIONED,
        })
    }

    fn rmdir(&mut self, url: &str, uid: u32, gid: u32) -> Result<usize> {
        let path = url.trim_matches('/');

        // println!("Rmdir '{}'", path);

        let scheme_name = &self.name;
        self.fs.tx(|tx| {
            let mut nodes = Vec::new();

            let Some((child, child_name)) =
                Self::path_nodes(scheme_name, tx, path, uid, gid, &mut nodes)?
            else {
                return Err(Error::new(ENOENT));
            };

            let Some((parent, _parent_name)) = nodes.last() else {
                return Err(Error::new(EPERM));
            };

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
        })
    }

    fn unlink(&mut self, url: &str, uid: u32, gid: u32) -> Result<usize> {
        let path = url.trim_matches('/');

        // println!("Unlink '{}'", path);

        let scheme_name = &self.name;
        self.fs.tx(|tx| {
            let mut nodes = Vec::new();

            let Some((child, child_name)) =
                Self::path_nodes(scheme_name, tx, path, uid, gid, &mut nodes)?
            else {
                return Err(Error::new(ENOENT));
            };

            let Some((parent, _parent_name)) = nodes.last() else {
                return Err(Error::new(EPERM));
            };

            if !parent.data().permission(uid, gid, Node::MODE_WRITE) {
                // println!("dir not writable {:o}", parent.1.mode);
                return Err(Error::new(EACCES));
            }

            if !child.data().is_dir() {
                if child.data().uid() != uid && uid != 0 {
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

        self.fmap
            .get_mut(&resource.node_ptr().id())
            .ok_or(Error::new(EBADFD))?
            .open_fds += 1;
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.files.insert(id, resource);

        Ok(id)
    }

    fn read(&mut self, id: usize, buf: &mut [u8], offset: u64, _fcntl_flags: u32) -> Result<usize> {
        // println!("Read {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let file = self.files.get_mut(&id).ok_or(Error::new(EBADF))?;
        self.fs.tx(|tx| file.read(buf, offset, tx))
    }

    fn write(&mut self, id: usize, buf: &[u8], offset: u64, _fcntl_flags: u32) -> Result<usize> {
        // println!("Write {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let file = self.files.get_mut(&id).ok_or(Error::new(EBADF))?;
        self.fs.tx(|tx| file.write(buf, offset, tx))
    }

    fn fsize(&mut self, id: usize) -> Result<u64> {
        // println!("Seek {}, {} {}", id, pos, whence);
        let file = self.files.get_mut(&id).ok_or(Error::new(EBADF))?;
        self.fs.tx(|tx| file.fsize(tx))
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

    //TODO: this function has too much code, try to simplify it
    fn frename(&mut self, id: usize, url: &str, uid: u32, gid: u32) -> Result<usize> {
        let new_path = url.trim_matches('/');

        // println!("Frename {}, {} from {}, {}", id, new_path, uid, gid);

        if let Some(file) = self.files.get_mut(&id) {
            //TODO: Check for EINVAL
            // The new pathname contained a path prefix of the old, or, more generally,
            // an attempt was made to make a directory a subdirectory of itself.

            let mut old_name = String::new();
            for part in file.path().split('/') {
                if !part.is_empty() {
                    old_name = part.to_string();
                }
            }
            if old_name.is_empty() {
                return Err(Error::new(EPERM));
            }

            let mut new_name = String::new();
            for part in new_path.split('/') {
                if !part.is_empty() {
                    new_name = part.to_string();
                }
            }
            if new_name.is_empty() {
                return Err(Error::new(EPERM));
            }

            let scheme_name = &self.name;
            self.fs.tx(|tx| {
                let orig_parent_ptr = match file.parent_ptr_opt() {
                    Some(some) => some,
                    None => {
                        // println!("orig is root");
                        return Err(Error::new(EBUSY));
                    }
                };

                let orig_node = tx.read_tree(file.node_ptr())?;

                if !orig_node.data().owner(uid) {
                    // println!("orig_node not owned by caller {}", uid);
                    return Err(Error::new(EACCES));
                }

                let mut new_nodes = Vec::new();
                let new_node_opt =
                    Self::path_nodes(scheme_name, tx, new_path, uid, gid, &mut new_nodes)?;

                if let Some((ref new_parent, _)) = new_nodes.last() {
                    if !new_parent.data().owner(uid) {
                        // println!("new_parent not owned by caller {}", uid);
                        return Err(Error::new(EACCES));
                    }

                    if let Some((ref new_node, _)) = new_node_opt {
                        if !new_node.data().owner(uid) {
                            // println!("new dir not owned by caller {}", uid);
                            return Err(Error::new(EACCES));
                        }

                        if new_node.data().is_dir() {
                            if !orig_node.data().is_dir() {
                                // println!("orig_node is file, new is dir");
                                return Err(Error::new(EACCES));
                            }

                            let mut children = Vec::new();
                            tx.child_nodes(new_node.ptr(), &mut children)?;

                            if !children.is_empty() {
                                // println!("new dir not empty");
                                return Err(Error::new(ENOTEMPTY));
                            }
                        } else {
                            if orig_node.data().is_dir() {
                                // println!("orig_node is dir, new is file");
                                return Err(Error::new(ENOTDIR));
                            }
                        }
                    }

                    tx.rename_node(orig_parent_ptr, &old_name, new_parent.ptr(), &new_name)?;

                    file.set_path(new_path);
                    Ok(0)
                } else {
                    Err(Error::new(EPERM))
                }
            })
        } else {
            Err(Error::new(EBADF))
        }
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
        let file = self.files.get_mut(&id).ok_or(Error::new(EBADF))?;
        let fmaps = &mut self.fmap;

        self.fs.tx(|tx| file.sync(fmaps, tx))
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

    fn mmap_prep(&mut self, id: usize, offset: u64, size: usize, flags: MapFlags) -> Result<usize> {
        let file = self.files.get_mut(&id).ok_or(Error::new(EBADF))?;
        let fmaps = &mut self.fmap;

        self.fs.tx(|tx| file.fmap(fmaps, flags, size, offset, tx))
    }
    #[allow(unused_variables)]
    fn munmap(&mut self, id: usize, offset: u64, size: usize, flags: MunmapFlags) -> Result<usize> {
        let file = self.files.get_mut(&id).ok_or(Error::new(EBADF))?;
        let fmaps = &mut self.fmap;

        self.fs.tx(|tx| file.funmap(fmaps, offset, size, tx))
    }

    fn close(&mut self, id: usize) -> Result<usize> {
        // println!("Close {}", id);
        let file = self.files.remove(&id).ok_or(Error::new(EBADF))?;
        let file_info = self
            .fmap
            .get_mut(&file.node_ptr().id())
            .ok_or(Error::new(EBADFD))?;

        file_info.open_fds = file_info
            .open_fds
            .checked_sub(1)
            .expect("open_fds not tracked correctly");

        // TODO: If open_fds reaches zero and there are no hardlinks (directory entries) to any
        // particular inode, remove that inode here.

        Ok(0)
    }
}
