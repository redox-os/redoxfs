use std::collections::BTreeMap;
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use redox_scheme::{scheme::SchemeSync, CallerCtx, OpenResult, SendFdRequest, Socket};
use syscall::data::{Stat, StatVfs, TimeSpec};
use syscall::dirent::DirentBuf;
use syscall::error::{
    Error, Result, EACCES, EBADF, EBUSY, EEXIST, EINVAL, EISDIR, ELOOP, ENOENT, ENOTDIR, ENOTEMPTY,
    EOPNOTSUPP, EPERM, EXDEV,
};
use syscall::flag::{
    EventFlags, MapFlags, O_ACCMODE, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_RDONLY, O_RDWR,
    O_STAT, O_SYMLINK, O_TRUNC, O_WRONLY,
};
use syscall::schemev2::NewFdFlags;
use syscall::FobtainFdFlags;
use syscall::FsCall;
use syscall::MunmapFlags;

use redox_path::{
    canonicalize_to_standard, canonicalize_using_cwd, canonicalize_using_scheme, scheme_path,
    RedoxPath,
};

use crate::{Disk, FileSystem, Node, Transaction, TreeData, TreePtr, BLOCK_SIZE};

use super::resource::{DirResource, Entry, FileMmapInfo, FileResource, Resource};

enum Handle<D: Disk> {
    Resource(Box<dyn Resource<D>>),
    SchemeRoot,
}

pub struct FileScheme<'sock, D: Disk> {
    scheme_name: String,
    mounted_path: String,
    pub(crate) fs: FileSystem<D>,
    socket: &'sock Socket,
    next_id: AtomicUsize,
    handles: BTreeMap<usize, Handle<D>>,
    fmap: super::resource::Fmaps,

    // Map of file id to other scheme's file descriptor.
    other_scheme_fd_map: BTreeMap<u32, usize>,
}

impl<'sock, D: Disk> FileScheme<'sock, D> {
    pub fn new(
        scheme_name: String,
        mounted_path: String,
        fs: FileSystem<D>,
        socket: &'sock Socket,
    ) -> FileScheme<'sock, D> {
        FileScheme {
            scheme_name,
            mounted_path,
            fs,
            socket,
            next_id: AtomicUsize::new(1),
            handles: BTreeMap::new(),
            fmap: BTreeMap::new(),
            other_scheme_fd_map: BTreeMap::new(),
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
            if let Some((next_node, next_node_name)) = Self::path_nodes(
                scheme_name,
                tx,
                TreePtr::root(),
                &target_reference,
                uid,
                gid,
                nodes,
            )? {
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

    fn handle_connect(&mut self, id: usize, payload: &mut [u8]) -> Result<usize> {
        let Some(Handle::Resource(resource)) = self.handles.get(&id) else {
            return Err(Error::new(EBADF));
        };
        let inode_id = resource.node_ptr().id();
        let target_fd = self
            .other_scheme_fd_map
            .get(&inode_id)
            .ok_or(Error::new(EBADF))?;
        let len = libredox::call::get_socket_token(*target_fd, payload)?;
        return Ok(len);
    }

    fn open(&mut self, url: &str, flags: usize, ctx: &CallerCtx) -> Result<OpenResult> {
        self.open_internal(TreePtr::root(), url, flags, ctx)
    }

    fn open_internal(
        &mut self,
        start_ptr: TreePtr<Node>,
        url: &str,
        flags: usize,
        ctx: &CallerCtx,
    ) -> Result<OpenResult> {
        let CallerCtx { uid, gid, .. } = *ctx;

        let path = url.trim_matches('/');

        // println!("Open '{}' {:X}", &path, flags);

        //TODO: try to move things into one transaction
        let scheme_name = &self.scheme_name;
        let mut nodes = Vec::new();
        let node_opt = self
            .fs
            .tx(|tx| Self::path_nodes(scheme_name, tx, start_ptr, path, uid, gid, &mut nodes))?;
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
                                data.push(Entry {
                                    node_ptr: child.node_ptr(),
                                    name: child_name.to_string(),
                                });
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
                    return self.open(&resolved, flags, ctx);
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

        let node_ptr = resource.node_ptr();
        {
            let fmap_info = self
                .fmap
                .entry(node_ptr.id())
                .or_insert_with(FileMmapInfo::new);
            if !fmap_info.in_use() {
                // Notify filesystem of open
                self.fs.tx(|tx| tx.on_open_node(node_ptr))?;
            }
            fmap_info.open_fds += 1;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles.insert(id, Handle::Resource(resource));

        Ok(OpenResult::ThisScheme {
            number: id,
            flags: NewFdFlags::POSITIONED,
        })
    }

    fn path_nodes(
        scheme_name: &str,
        tx: &mut Transaction<D>,
        start_ptr: TreePtr<Node>,
        path: &str,
        uid: u32,
        gid: u32,
        nodes: &mut Vec<(TreeData<Node>, String)>,
    ) -> Result<Option<(TreeData<Node>, String)>> {
        let mut parts = path.split('/').filter(|part| !part.is_empty());
        let mut part_opt: Option<&str> = None;
        let mut node_ptr = start_ptr;
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

impl<'sock, D: Disk> SchemeSync for FileScheme<'sock, D> {
    fn scheme_root(&mut self) -> Result<usize> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles.insert(id, Handle::SchemeRoot);
        Ok(id)
    }

    fn openat(
        &mut self,
        dirfd: usize,
        path: &str,
        flags: usize,
        _fcntl_flags: u32,
        ctx: &CallerCtx,
    ) -> Result<OpenResult> {
        let dir_node_ptr = match self.handles.get(&dirfd).ok_or(Error::new(EBADF))? {
            // If pathname is absolute, then dirfd is ignored.
            Handle::Resource(dir_resource) if !path.starts_with('/') => {
                // only allow dirresource as base for openat
                dir_resource.node_ptr()
            }
            _ => TreePtr::root(),
        };
        self.open_internal(dir_node_ptr, path, flags, ctx)
    }

    fn unlinkat(&mut self, dirfd: usize, url: &str, flags: usize, ctx: &CallerCtx) -> Result<()> {
        let path = url.trim_matches('/');
        let uid = ctx.uid;
        let gid = ctx.gid;

        let start_ptr = match self.handles.get(&dirfd).ok_or(Error::new(EBADF))? {
            Handle::Resource(dir_resource) => dir_resource.node_ptr(),
            Handle::SchemeRoot => TreePtr::root(),
        };

        // println!("Unlinkat '{}' flags: {:X}", path, flags);

        let scheme_name = &self.scheme_name;

        let unlink_result = self.fs.tx(|tx| {
            let mut nodes = Vec::new();

            let Some((child, child_name)) =
                Self::path_nodes(scheme_name, tx, start_ptr, path, uid, gid, &mut nodes)?
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

            // Check AT_REMOVEDIR
            if flags & syscall::AT_REMOVEDIR == syscall::AT_REMOVEDIR {
                // --- rmdir ---
                if child.data().is_dir() {
                    if !child.data().permission(uid, gid, Node::MODE_WRITE) {
                        return Err(Error::new(EACCES));
                    }
                    tx.remove_node(parent.ptr(), &child_name, Node::MODE_DIR)
                } else {
                    Err(Error::new(ENOTDIR))
                }
            } else {
                // --- unlink ---
                if !child.data().is_dir() {
                    if child.data().uid() != uid && uid != 0 {
                        // println!("file not owned by current user {}", parent.1.uid);
                        return Err(Error::new(EACCES));
                    }

                    let mode = if child.data().is_symlink() {
                        Node::MODE_SYMLINK
                    } else if child.data().is_sock() {
                        Node::MODE_SOCK
                    } else {
                        Node::MODE_FILE
                    };

                    tx.remove_node(parent.ptr(), &child_name, mode)
                } else {
                    Err(Error::new(EISDIR))
                }
            }
        });

        let Some(node_id) = unlink_result? else {
            return Ok(());
        };

        if let Some(fd) = self.other_scheme_fd_map.remove(&node_id) {
            let _ = syscall::close(fd);
        }

        Ok(())
    }

    /* Resource operations */
    fn read(
        &mut self,
        id: usize,
        buf: &mut [u8],
        offset: u64,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        // println!("Read {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let Some(Handle::Resource(file)) = self.handles.get_mut(&id) else {
            return Err(Error::new(EBADF));
        };
        self.fs.tx(|tx| file.read(buf, offset, tx))
    }

    fn write(
        &mut self,
        id: usize,
        buf: &[u8],
        offset: u64,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        // println!("Write {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let Some(Handle::Resource(file)) = self.handles.get_mut(&id) else {
            return Err(Error::new(EBADF));
        };
        self.fs.tx(|tx| file.write(buf, offset, tx))
    }

    fn fsize(&mut self, id: usize, _ctx: &CallerCtx) -> Result<u64> {
        // println!("Seek {}, {} {}", id, pos, whence);
        let Some(Handle::Resource(file)) = self.handles.get_mut(&id) else {
            return Err(Error::new(EBADF));
        };
        self.fs.tx(|tx| file.fsize(tx))
    }

    fn fchmod(&mut self, id: usize, mode: u16, _ctx: &CallerCtx) -> Result<()> {
        if let Some(Handle::Resource(file)) = self.handles.get_mut(&id) {
            self.fs.tx(|tx| file.fchmod(mode, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fchown(&mut self, id: usize, new_uid: u32, new_gid: u32, _ctx: &CallerCtx) -> Result<()> {
        if let Some(Handle::Resource(file)) = self.handles.get_mut(&id) {
            self.fs.tx(|tx| file.fchown(new_uid, new_gid, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fcntl(&mut self, id: usize, cmd: usize, arg: usize, _ctx: &CallerCtx) -> Result<usize> {
        if let Some(Handle::Resource(file)) = self.handles.get_mut(&id) {
            file.fcntl(cmd, arg)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fevent(&mut self, id: usize, _flags: EventFlags, _ctx: &CallerCtx) -> Result<EventFlags> {
        if let Some(Handle::Resource(_file)) = self.handles.get(&id) {
            // EPERM is returned for handles that are always readable or writable
            Err(Error::new(EPERM))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8], _ctx: &CallerCtx) -> Result<usize> {
        // println!("Fpath {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        if let Some(Handle::Resource(file)) = self.handles.get(&id) {
            let mounted_path = self.mounted_path.as_bytes();

            let mut i = 0;
            while i < buf.len() && i < mounted_path.len() {
                buf[i] = mounted_path[i];
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
    fn flink(&mut self, id: usize, url: &str, ctx: &CallerCtx) -> Result<usize> {
        let new_path = url.trim_matches('/');
        let uid = ctx.uid;
        let gid = ctx.gid;

        // println!("Flink {}, {} from {}, {}", id, new_path, uid, gid);

        if let Some(Handle::Resource(file)) = self.handles.get_mut(&id) {
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

            let scheme_name = &self.scheme_name;
            self.fs.tx(|tx| {
                let _orig_parent_ptr = match file.parent_ptr_opt() {
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
                let new_node_opt = Self::path_nodes(
                    scheme_name,
                    tx,
                    TreePtr::root(),
                    new_path,
                    uid,
                    gid,
                    &mut new_nodes,
                )?;

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

                    tx.link_node(new_parent.ptr(), &new_name, orig_node.ptr())?;

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

    //TODO: this function has too much code, try to simplify it
    fn frename(&mut self, id: usize, url: &str, ctx: &CallerCtx) -> Result<usize> {
        let new_path = url.trim_matches('/');
        let uid = ctx.uid;
        let gid = ctx.gid;

        // println!("Frename {}, {} from {}, {}", id, new_path, uid, gid);

        if let Some(Handle::Resource(file)) = self.handles.get_mut(&id) {
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

            let scheme_name = &self.scheme_name;
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
                let new_node_opt = Self::path_nodes(
                    scheme_name,
                    tx,
                    TreePtr::root(),
                    new_path,
                    uid,
                    gid,
                    &mut new_nodes,
                )?;

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

    fn fstat(&mut self, id: usize, stat: &mut Stat, _ctx: &CallerCtx) -> Result<()> {
        // println!("Fstat {}, {:X}", id, stat as *mut Stat as usize);
        if let Some(Handle::Resource(file)) = self.handles.get(&id) {
            self.fs.tx(|tx| file.stat(stat, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fstatvfs(&mut self, id: usize, stat: &mut StatVfs, _ctx: &CallerCtx) -> Result<()> {
        if let Some(Handle::Resource(_file)) = self.handles.get(&id) {
            stat.f_bsize = BLOCK_SIZE as u32;
            stat.f_blocks = self.fs.header.size() / (stat.f_bsize as u64);
            stat.f_bfree = self.fs.allocator().free();
            stat.f_bavail = stat.f_bfree;

            Ok(())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fsync(&mut self, id: usize, _ctx: &CallerCtx) -> Result<()> {
        // println!("Fsync {}", id);
        let Some(Handle::Resource(file)) = self.handles.get_mut(&id) else {
            return Err(Error::new(EBADF));
        };
        let fmaps = &mut self.fmap;

        self.fs.tx(|tx| file.sync(fmaps, tx))
    }

    fn ftruncate(&mut self, id: usize, len: u64, _ctx: &CallerCtx) -> Result<()> {
        // println!("Ftruncate {}, {}", id, len);
        if let Some(Handle::Resource(file)) = self.handles.get_mut(&id) {
            self.fs.tx(|tx| file.truncate(len, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn futimens(&mut self, id: usize, times: &[TimeSpec], _ctx: &CallerCtx) -> Result<()> {
        // println!("Futimens {}, {}", id, times.len());
        if let Some(Handle::Resource(file)) = self.handles.get_mut(&id) {
            self.fs.tx(|tx| file.utimens(times, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn getdents<'buf>(
        &mut self,
        id: usize,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        if let Some(Handle::Resource(file)) = self.handles.get_mut(&id) {
            self.fs.tx(|tx| file.getdents(buf, opaque_offset, tx))
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn mmap_prep(
        &mut self,
        id: usize,
        offset: u64,
        size: usize,
        flags: MapFlags,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let Some(Handle::Resource(file)) = self.handles.get_mut(&id) else {
            return Err(Error::new(EBADF));
        };
        let fmaps = &mut self.fmap;

        self.fs.tx(|tx| file.fmap(fmaps, flags, size, offset, tx))
    }
    #[allow(unused_variables)]
    fn munmap(
        &mut self,
        id: usize,
        offset: u64,
        size: usize,
        flags: MunmapFlags,
        _ctx: &CallerCtx,
    ) -> Result<()> {
        let Some(Handle::Resource(file)) = self.handles.get_mut(&id) else {
            return Err(Error::new(EBADF));
        };
        let fmaps = &mut self.fmap;

        self.fs.tx(|tx| file.funmap(fmaps, offset, size, tx))
    }

    fn on_close(&mut self, id: usize) {
        // println!("Close {}", id);
        let Some(Handle::Resource(file)) = self.handles.remove(&id) else {
            return;
        };
        let node_ptr = file.node_ptr();
        let Some(file_info) = self.fmap.get_mut(&node_ptr.id()) else {
            return;
        };

        file_info.open_fds = file_info
            .open_fds
            .checked_sub(1)
            .expect("open_fds not tracked correctly");

        // Check if node no longer in use
        if !file_info.in_use() {
            // Notify filesystem of close
            if let Err(err) = self.fs.tx(|tx| tx.on_close_node(node_ptr)) {
                log::error!("failed to close node {}: {}", node_ptr.id(), err);
            }

            /*TODO: leaks memory, but why?
            // Remove from fmap list
            self.fmap.remove(&node_ptr.id());
            */
        }
    }

    fn on_sendfd(&mut self, sendfd_request: &SendFdRequest) -> Result<usize> {
        let ctx = sendfd_request.caller();
        let uid = ctx.uid;
        let gid = ctx.gid;

        let Some(Handle::Resource(parent_resource)) = self.handles.get(&sendfd_request.id()) else {
            return Err(Error::new(EBADF));
        };

        let mut new_fd = usize::MAX;
        if let Err(e) = sendfd_request.obtain_fd(
            &self.socket,
            FobtainFdFlags::empty(),
            std::slice::from_mut(&mut new_fd),
        ) {
            return Err(e);
        }

        let parent_resource_ptr = parent_resource.node_ptr();

        let parent_node = self.fs.tx(|tx| tx.read_tree(parent_resource_ptr))?;
        if !parent_node.data().is_dir() {
            return Err(Error::new(ENOTDIR));
        }
        if !parent_node.data().permission(uid, gid, Node::MODE_WRITE) {
            return Err(Error::new(EACCES));
        }
        let parent_path = parent_resource.path();

        // TODO: Move the PATH_MAX definition to a more appropriate place.
        const PATH_MAX: usize = 4096;
        let mut url_buf = [0u8; PATH_MAX];
        let url_len = syscall::fpath(new_fd, &mut url_buf)?;
        let url_str = str::from_utf8(&url_buf[..url_len]).map_err(|_| Error::new(EINVAL))?;
        let redox_path = RedoxPath::from_absolute(url_str).ok_or(Error::new(EINVAL))?;
        let (_, path) = redox_path.as_parts().ok_or(Error::new(EINVAL))?;

        let mut last_part = String::new();
        for part in path.as_ref().split('/') {
            if !part.is_empty() {
                last_part = part.to_string();
            }
        }

        let (resource, node_id): (Box<dyn Resource<D>>, u32) = if !last_part.is_empty() {
            let mut stat = Stat::default();
            syscall::fstat(new_fd, &mut stat)?;
            let mode_type = stat.st_mode & Node::MODE_TYPE;

            let flags = 0o777;
            let node_ptr = self.fs.tx(|tx| {
                if tx.find_node(parent_resource_ptr, &last_part).is_ok() {
                    // If the file already exists, we cannot create it again
                    return Err(Error::new(EEXIST));
                }

                let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let mut node = tx.create_node(
                    parent_resource_ptr,
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

            let file_path = format!("{parent_path}/{last_part}");
            let node_id = node_ptr.id();

            (
                Box::new(FileResource::new(
                    file_path,
                    Some(parent_resource_ptr),
                    node_ptr,
                    flags,
                    uid,
                )),
                node_id,
            )
        } else {
            return Err(Error::new(EINVAL));
        };

        let node_ptr = resource.node_ptr();
        {
            let fmap_info = self
                .fmap
                .entry(node_ptr.id())
                .or_insert_with(FileMmapInfo::new);
            if !fmap_info.in_use() {
                // Notify filesystem of open
                self.fs.tx(|tx| tx.on_open_node(node_ptr))?;
            }
            fmap_info.open_fds += 1;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles.insert(id, Handle::Resource(resource));
        self.other_scheme_fd_map.insert(node_id, new_fd);
        Ok(new_fd)
    }

    fn call(
        &mut self,
        id: usize,
        payload: &mut [u8],
        metadata: &[u64],
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let Some(verb) = FsCall::try_from_raw(metadata[0] as usize) else {
            return Err(Error::new(EINVAL));
        };
        match verb {
            FsCall::Connect => self.handle_connect(id, payload),
            _ => Err(Error::new(EOPNOTSUPP)),
        }
    }
}
