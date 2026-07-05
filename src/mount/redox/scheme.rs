use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::mem;
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use libredox::Fd;
use redox_path::RedoxReference;
use redox_path::RedoxScheme;
use redox_path::RedoxStr;
use redox_scheme::{scheme::SchemeSync, CallerCtx, OpenResult, SendFdRequest, Socket};
use smallvec::SmallVec;
use syscall::data::{Stat, StatVfs, StdFsCallMeta, TimeSpec};
use syscall::dirent::DirentBuf;
use syscall::error::{
    Error, Result, EACCES, EBADF, EBUSY, EEXIST, EINVAL, EISDIR, ELOOP, ENOENT, ENOTDIR, ENOTEMPTY,
    EOPNOTSUPP, EPERM, EXDEV,
};
use syscall::flag::{
    EventFlags, MapFlags, StdFsCallKind, O_ACCMODE, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW,
    O_RDONLY, O_RDWR, O_STAT, O_SYMLINK, O_TRUNC, O_WRONLY,
};
use syscall::schemev2::NewFdFlags;
use syscall::FobtainFdFlags;
use syscall::FsCall;
use syscall::MunmapFlags;

use redox_path::RedoxPath;

use crate::{Disk, FileSystem, Node, Transaction, TreeData, TreePtr, BLOCK_SIZE};

use super::resource::{DirResource, Entry, FileMmapInfo, FileResource, Resource};

enum Handle<D: Disk> {
    ResourceDir((DirResource, PhantomData<D>)),
    ResourceFile((FileResource, PhantomData<D>)),
    SchemeRoot,
}

impl<D: Disk> Handle<D> {
    pub fn resource(&self) -> Result<&dyn Resource<D>> {
        match self {
            Handle::ResourceDir((dir_resource, _)) => Ok(dir_resource as &dyn Resource<D>),
            Handle::ResourceFile((file_resource, _)) => Ok(file_resource),
            Handle::SchemeRoot => Err(Error::new(EBADF)),
        }
    }
    pub fn resource_mut(&mut self) -> Result<&mut dyn Resource<D>> {
        match self {
            Handle::ResourceDir((dir_resource, _)) => Ok(dir_resource as &mut dyn Resource<D>),
            Handle::ResourceFile((file_resource, _)) => Ok(file_resource),
            Handle::SchemeRoot => Err(Error::new(EBADF)),
        }
    }
    pub fn get_resource(res: Option<&Self>) -> Result<&dyn Resource<D>> {
        res.ok_or(Error::new(EBADF)).and_then(|s| s.resource())
    }
    pub fn get_resource_mut(res: Option<&mut Self>) -> Result<&mut dyn Resource<D>> {
        res.ok_or(Error::new(EBADF)).and_then(|s| s.resource_mut())
    }
    pub fn get_resource_or(res: Option<&Self>) -> Result<Option<&dyn Resource<D>>> {
        res.ok_or(Error::new(EBADF)).map(|s| s.resource().ok())
    }
}

pub struct FileScheme<'sock, D: Disk> {
    scheme_name: RedoxScheme<'sock>,
    mounted_path: String,
    pub(crate) fs: FileSystem<D>,
    socket: &'sock Socket,
    next_id: AtomicUsize,
    handles: BTreeMap<usize, Handle<D>>,
    fmap: super::resource::Fmaps,

    // Map of file id to other scheme's file descriptor.
    other_scheme_fd_map: BTreeMap<u32, Fd>,

    proc_creds_capability: Fd,
}

impl<'sock, D: Disk> FileScheme<'sock, D> {
    pub fn new(
        scheme_name: String,
        mounted_path: String,
        fs: FileSystem<D>,
        socket: &'sock Socket,
    ) -> Result<FileScheme<'sock, D>> {
        Ok(FileScheme {
            scheme_name: RedoxScheme::new(scheme_name)
                .expect("scheme name for FileScheme is not valid"),
            mounted_path,
            fs,
            socket,
            next_id: AtomicUsize::new(1),
            handles: BTreeMap::new(),
            fmap: BTreeMap::new(),
            other_scheme_fd_map: BTreeMap::new(),
            proc_creds_capability: {
                libredox::Fd::open(
                    "/scheme/proc/proc-creds-capability",
                    libredox::flag::O_RDONLY,
                    0,
                )?
            },
        })
    }

    /// Resolve a symbolic link of given `node`. `full_path` must be non-canonicalized path from root node.
    fn resolve_symlink<'a>(
        scheme_name: &RedoxScheme<'sock>,
        tx: &mut Transaction<D>,
        uid: u32,
        gid: u32,
        full_path: RedoxReference<'a>,
        node: TreeData<Node>,
        nodes: &mut SmallVec<[(TreeData<Node>, String); 16]>,
    ) -> Result<RedoxReference<'a>> {
        let atime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        // symbolic link is relative to this part of the url
        let mut working_dir = full_path.dirname();
        // node of the link
        let mut node = node;

        for _ in 0..64 {
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

            let path = str::from_utf8(&buf[..count]).or(Err(Error::new(EINVAL)))?;
            let path = RedoxStr::new(path).ok_or(Error::new(EINVAL))?;
            let target_reference = match path {
                RedoxStr::Absolute(redox_path) => {
                    if redox_path
                        .get_scheme()
                        .is_some_and(|s| s.as_ref() != scheme_name.as_ref())
                    {
                        return Err(Error::new(EXDEV));
                    }
                    redox_path.to_reference()
                }
                RedoxStr::Relative(redox_reference) => working_dir.join_checked(redox_reference),
            };

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
                    return Ok(target_reference.into_owned());
                }
                node = next_node;
                working_dir = target_reference.dirname()
            } else {
                return Err(Error::new(ENOENT));
            }
        }
        Err(Error::new(ELOOP))
    }

    fn handle_connect(&mut self, id: usize, payload: &mut [u8]) -> Result<usize> {
        let resource = Handle::get_resource(self.handles.get(&id))?;
        let inode_id = resource.node_ptr().id();
        let target_fd = self
            .other_scheme_fd_map
            .get(&inode_id)
            .ok_or(Error::new(EBADF))?;
        let len = libredox::call::get_socket_token(target_fd.raw(), payload)?;
        return Ok(len);
    }

    fn open(
        &mut self,
        url: RedoxReference<'_>,
        flags: usize,
        ctx: &CallerCtx,
    ) -> Result<OpenResult> {
        self.open_internal(TreePtr::root(), url, flags, ctx)
    }

    fn open_internal(
        &mut self,
        start_ptr: TreePtr<Node>,
        path: RedoxReference<'_>,
        flags: usize,
        ctx: &CallerCtx,
    ) -> Result<OpenResult> {
        let CallerCtx { uid, gid, .. } = *ctx;

        // println!("Open '{}' {:X}", &path, flags);

        //TODO: try to move things into one transaction
        let scheme_name = &self.scheme_name;
        let mut nodes = SmallVec::new();
        let node_opt = self
            .fs
            .tx(|tx| Self::path_nodes(scheme_name, tx, start_ptr, &path, uid, gid, &mut nodes))?;
        let parent_ptr_opt = nodes.last().map(|x| x.0.ptr());
        let handle: Handle<D> = match node_opt {
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

                        Handle::ResourceDir((
                            DirResource::new(
                                path.to_string(),
                                parent_ptr_opt,
                                node.ptr(),
                                Some(data),
                                uid,
                            ),
                            PhantomData,
                        ))
                    } else if flags & O_WRONLY == O_WRONLY {
                        // println!("{:X} & {:X}: EISDIR {}", flags, O_DIRECTORY, path);
                        return Err(Error::new(EISDIR));
                    } else {
                        Handle::ResourceDir((
                            DirResource::new(
                                path.to_string(),
                                parent_ptr_opt,
                                node.ptr(),
                                None,
                                uid,
                            ),
                            PhantomData,
                        ))
                    }
                } else if node.data().is_symlink()
                    && !(flags & O_STAT == O_STAT && flags & O_NOFOLLOW == O_NOFOLLOW)
                    && flags & O_SYMLINK != O_SYMLINK
                {
                    let mut resolve_nodes = SmallVec::new();
                    let resolved = self.fs.tx(|tx| {
                        Self::resolve_symlink(
                            scheme_name,
                            tx,
                            uid,
                            gid,
                            path,
                            node,
                            &mut resolve_nodes,
                        )
                    })?;
                    return self.open(resolved, flags, ctx);
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

                    Handle::ResourceFile((
                        FileResource::new(path.to_string(), parent_ptr_opt, node_ptr, flags, uid),
                        PhantomData,
                    ))
                }
            }
            None => {
                if flags & O_CREAT != O_CREAT {
                    return Err(Error::new(ENOENT));
                }
                let mut last_part = String::new();
                for part in path.as_ref().split('/') {
                    if !part.is_empty() {
                        last_part = part.to_string();
                    }
                }
                if last_part.is_empty() {
                    return Err(Error::new(EPERM));
                }
                let Some((parent, _parent_name)) = nodes.last() else {
                    return Err(Error::new(EPERM));
                };
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
                        mode_type as u16 | (flags as u16 & Node::MODE_PERM),
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
                    Handle::ResourceDir((
                        DirResource::new(path.to_string(), parent_ptr_opt, node_ptr, None, uid),
                        PhantomData,
                    ))
                } else {
                    Handle::ResourceFile((
                        FileResource::new(path.to_string(), parent_ptr_opt, node_ptr, flags, uid),
                        PhantomData,
                    ))
                }
            }
        };

        let node_ptr = handle.resource().unwrap().node_ptr();
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
        self.handles.insert(id, handle);

        Ok(OpenResult::ThisScheme {
            number: id,
            flags: NewFdFlags::POSITIONED,
        })
    }

    fn unlink_internal(
        &mut self,
        start_ptr: TreePtr<Node>,
        path: &RedoxReference<'_>,
        flags: usize,
        uid: u32,
        gid: u32,
    ) -> Result<()> {
        let scheme_name = &self.scheme_name;

        let unlink_result = self.fs.tx(|tx| {
            let mut nodes = SmallVec::new();

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

        let _ = self.other_scheme_fd_map.remove(&node_id);

        Ok(())
    }

    fn path_nodes(
        scheme_name: &RedoxScheme<'sock>,
        tx: &mut Transaction<D>,
        start_ptr: TreePtr<Node>,
        path: &RedoxReference<'_>,
        uid: u32,
        gid: u32,
        nodes: &mut SmallVec<[(TreeData<Node>, String); 16]>,
    ) -> Result<Option<(TreeData<Node>, String)>> {
        let mut parts = path
            .as_ref()
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".");
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
                    // url.push_str(scheme_name.as_ref());
                    // url.push(':');
                    for (_parent, parent_name) in nodes.iter() {
                        if !url.is_empty() {
                            url.push('/');
                        }
                        url.push_str(&parent_name);
                    }
                    let url = RedoxReference::new(url).ok_or(Error::new(EINVAL))?;
                    Self::resolve_symlink(scheme_name, tx, uid, gid, url, node, nodes)?;
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

pub fn resolve_path<'a, 'b, D: Disk>(
    dir: &'a dyn Resource<D>,
    path: RedoxReference<'b>,
) -> Result<RedoxReference<'b>> {
    let dirpath = RedoxReference::new(dir.path());
    let dirpath = dirpath.ok_or(Error::new(ENOENT))?;
    Ok(dirpath.join_checked(path))
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
        let path = RedoxReference::new(path).ok_or(Error::new(EINVAL))?;
        let path_to_open = match Handle::get_resource_or(self.handles.get(&dirfd))? {
            // If pathname is absolute, then dirfd is ignored.
            Some(res) if path.is_relative() => resolve_path(res, path)?,
            _ => path,
        };
        self.open_internal(
            TreePtr::root(),
            path_to_open.to_relative().canonical(),
            flags,
            ctx,
        )
    }

    fn unlinkat(&mut self, dirfd: usize, path: &str, flags: usize, ctx: &CallerCtx) -> Result<()> {
        let uid = ctx.uid;
        let gid = ctx.gid;
        let path = RedoxReference::new(path).ok_or(Error::new(EINVAL))?;
        let path = match Handle::get_resource_or(self.handles.get(&dirfd))? {
            // If pathname is absolute, then dirfd is ignored.
            Some(res) if path.is_relative() => resolve_path(res, path)?,
            _ => path,
        };
        let start_ptr = TreePtr::root();

        // println!("Unlinkat '{}' flags: {:X}", path, flags);

        self.unlink_internal(start_ptr, &path.canonical(), flags, uid, gid)
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
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        self.fs.tx(|tx| file.read(&mut self.fmap, buf, offset, tx))
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
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        self.fs.tx(|tx| file.write(&mut self.fmap, buf, offset, tx))
    }

    fn fsize(&mut self, id: usize, _ctx: &CallerCtx) -> Result<u64> {
        // println!("Seek {}, {} {}", id, pos, whence);
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        self.fs.tx(|tx| file.fsize(tx))
    }

    fn fchmod(&mut self, id: usize, mode: u16, _ctx: &CallerCtx) -> Result<()> {
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        self.fs.tx(|tx| file.fchmod(mode, tx))
    }

    fn fchown(&mut self, id: usize, new_uid: u32, new_gid: u32, _ctx: &CallerCtx) -> Result<()> {
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        self.fs.tx(|tx| file.fchown(new_uid, new_gid, tx))
    }

    fn fcntl(&mut self, id: usize, cmd: usize, arg: usize, _ctx: &CallerCtx) -> Result<usize> {
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        file.fcntl(cmd, arg)
    }

    fn fevent(&mut self, id: usize, _flags: EventFlags, _ctx: &CallerCtx) -> Result<EventFlags> {
        let _file = Handle::get_resource(self.handles.get(&id))?;
        // EPERM is returned for handles that are always readable or writable
        Err(Error::new(EPERM))
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8], _ctx: &CallerCtx) -> Result<usize> {
        // println!("Fpath {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let file = Handle::get_resource(self.handles.get(&id))?;
        let mounted_path = self.mounted_path.as_bytes();

        let mut i = 0;
        while i < buf.len() && i < mounted_path.len() {
            buf[i] = mounted_path[i];
            i += 1;
        }

        let path = file.path().as_bytes();
        if !path.is_empty() {
            if i < buf.len() {
                buf[i] = b'/';
                i += 1;
            }

            let mut j = 0;
            while i < buf.len() && j < path.len() {
                buf[i] = path[j];
                i += 1;
                j += 1;
            }
        }

        Ok(i)
    }

    //TODO: this function has too much code, try to simplify it
    fn flink(&mut self, id: usize, url: &str, ctx: &CallerCtx) -> Result<usize> {
        let new_path = RedoxReference::new(url)
            .ok_or(Error::new(EINVAL))?
            .canonical();
        let uid = ctx.uid;
        let gid = ctx.gid;

        // println!("Flink {}, {} from {}, {}", id, new_path, uid, gid);

        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
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
        for part in new_path.as_ref().split('/') {
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

            let mut new_nodes = SmallVec::new();
            let new_node_opt = Self::path_nodes(
                scheme_name,
                tx,
                TreePtr::root(),
                &new_path,
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

                file.set_path(new_path.as_ref());
                Ok(0)
            } else {
                Err(Error::new(EPERM))
            }
        })
    }

    //TODO: this function has too much code, try to simplify it
    fn frename(&mut self, id: usize, url: &str, ctx: &CallerCtx) -> Result<usize> {
        let new_path = RedoxReference::new(url)
            .ok_or(Error::new(EINVAL))?
            .canonical();
        let uid = ctx.uid;
        let gid = ctx.gid;

        // println!("Frename {}, {} from {}, {}", id, new_path, uid, gid);

        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
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
        for part in new_path.as_ref().split('/') {
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

            let mut new_nodes = SmallVec::new();
            let new_node_opt = Self::path_nodes(
                scheme_name,
                tx,
                TreePtr::root(),
                &new_path,
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

                file.set_path(new_path.as_ref());
                Ok(0)
            } else {
                Err(Error::new(EPERM))
            }
        })
    }

    fn fstat(&mut self, id: usize, stat: &mut Stat, _ctx: &CallerCtx) -> Result<()> {
        // println!("Fstat {}, {:X}", id, stat as *mut Stat as usize);
        let file = Handle::get_resource(self.handles.get(&id))?;
        self.fs.tx(|tx| file.stat(stat, tx))
    }

    fn fstatvfs(&mut self, id: usize, stat: &mut StatVfs, _ctx: &CallerCtx) -> Result<()> {
        let _file = Handle::get_resource(self.handles.get(&id))?;
        stat.f_bsize = BLOCK_SIZE as u32;
        stat.f_blocks = self.fs.header.size() / (stat.f_bsize as u64);
        stat.f_bfree = self.fs.allocator().free();
        stat.f_bavail = stat.f_bfree;

        Ok(())
    }

    fn fsync(&mut self, id: usize, _ctx: &CallerCtx) -> Result<()> {
        // println!("Fsync {}", id);
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        let fmaps = &mut self.fmap;

        self.fs.tx(|tx| file.sync(fmaps, tx))
    }

    fn ftruncate(&mut self, id: usize, len: u64, _ctx: &CallerCtx) -> Result<()> {
        // println!("Ftruncate {}, {}", id, len);
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        self.fs.tx(|tx| file.truncate(len, tx))
    }

    fn futimens(&mut self, id: usize, times: &[TimeSpec], _ctx: &CallerCtx) -> Result<()> {
        // println!("Futimens {}, {}", id, times.len());
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        self.fs.tx(|tx| file.utimens(times, tx))
    }

    fn getdents<'buf>(
        &mut self,
        id: usize,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        self.fs.tx(|tx| file.getdents(buf, opaque_offset, tx))
    }

    fn mmap_prep(
        &mut self,
        id: usize,
        offset: u64,
        size: usize,
        flags: MapFlags,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        let fmaps = &mut self.fmap;

        self.fs.tx(|tx| file.fmap(fmaps, flags, size, offset, tx))
    }
    fn munmap(
        &mut self,
        id: usize,
        offset: u64,
        size: usize,
        _flags: MunmapFlags,
        _ctx: &CallerCtx,
    ) -> Result<()> {
        let file = Handle::get_resource_mut(self.handles.get_mut(&id))?;
        let fmaps = &mut self.fmap;

        self.fs.tx(|tx| file.funmap(fmaps, offset, size, tx))
    }

    fn on_close(&mut self, id: usize) {
        // println!("Close {}", id);
        let Some(file) = self.handles.remove(&id) else {
            return;
        };
        let Ok(resource) = file.resource() else {
            return;
        };
        let node_ptr = resource.node_ptr();
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

        let parent_resource = Handle::get_resource(self.handles.get(&sendfd_request.id()))?;

        let mut new_fd = usize::MAX;
        if let Err(e) = sendfd_request.obtain_fd(
            &self.socket,
            FobtainFdFlags::empty(),
            std::slice::from_mut(&mut new_fd),
        ) {
            return Err(e);
        }
        let other_scheme_fd = Fd::new(new_fd);

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
        let url_len = other_scheme_fd.fpath(&mut url_buf)?;
        let url_str = str::from_utf8(&url_buf[..url_len]).map_err(|_| Error::new(EINVAL))?;
        let redox_path = RedoxPath::from_absolute(url_str).ok_or(Error::new(EINVAL))?;
        let (_, path) = redox_path.as_parts().ok_or(Error::new(EINVAL))?;

        let mut last_part = String::new();
        for part in path.as_ref().split('/') {
            if !part.is_empty() {
                last_part = part.to_string();
            }
        }

        if last_part.is_empty() {
            return Err(Error::new(EINVAL));
        }
        let (resource, node_id) = {
            let stat = other_scheme_fd.stat()?;
            let mode_type = stat.st_mode as u16 & Node::MODE_TYPE;

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
                FileResource::new(file_path, Some(parent_resource_ptr), node_ptr, flags, uid),
                node_id,
            )
        };

        let node_ptr = (&resource as &'_ dyn Resource<D>).node_ptr();
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
        self.handles
            .insert(id, Handle::ResourceFile((resource, PhantomData)));
        self.other_scheme_fd_map.insert(node_id, other_scheme_fd);
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

    fn std_fs_call(
        &mut self,
        id: usize,
        kind: StdFsCallKind,
        _payload: &mut [u8],
        metadata: StdFsCallMeta,
        ctx: &CallerCtx,
    ) -> Result<usize> {
        match kind {
            StdFsCallKind::Fchown => {
                let (new_uid, new_gid) = (metadata.arg1 as u32, metadata.arg2 >> 32 as u32);
                let (_pid, uid, gid) = get_uid_gid_from_pid(&self.proc_creds_capability, ctx.pid)?;
                if uid != 0 && (uid != ctx.uid || gid != ctx.gid) {
                    return Err(Error::new(EPERM));
                }
                self.fchown(id, new_uid, new_gid as u32, ctx).map(|_| 0)
            }
            /* TODO: Support Unlinkat using std_fs_call
            Unlinkat => {
                let path = unsafe { str::from_utf8_unchecked(payload) };
                let flags = metadata.arg1;
                let dir_node_ptr = match self.handles.get(&id).ok_or(Error::new(EBADF))? {
                    // If pathname is absolute, then dirfd is ignored.
                    Handle::Resource(dir_resource) if !path.starts_with('/') => {
                        // only allow dirresource as base for openat
                        dir_resource.node_ptr()
                    }
                    _ => TreePtr::root(),
                };
                let (_pid, uid, gid) = get_uid_gid_from_pid(&self.proc_creds_capability, ctx.pid)?;
                self.unlink_internal(dir_node_ptr, path, *flags as usize, uid, gid)
                    .map(|_| 0)
            }
            */
            _ => Err(Error::new(EOPNOTSUPP)),
        }
    }

    fn inode(&self, id: usize) -> Result<usize> {
        let resource = Handle::get_resource(self.handles.get(&id))?;
        Ok(resource.node_ptr().id() as usize)
    }
}

fn get_uid_gid_from_pid(cap_fd: &Fd, target_pid: usize) -> Result<(u32, u32, u32)> {
    let mut buffer = [0u8; mem::size_of::<libredox::protocol::ProcMeta>()];
    let _ = libredox::call::get_proc_credentials(cap_fd.raw(), target_pid, &mut buffer).map_err(
        |e| {
            eprintln!(
                "Failed to get process credentials for pid {}: {:?}",
                target_pid, e
            );
            Error::new(EINVAL)
        },
    )?;
    let mut cursor = 0;
    let pid = read_u32(&buffer, cursor)?;
    cursor += mem::size_of::<u32>() * 3;
    let uid = read_u32(&buffer, cursor)?;
    cursor += mem::size_of::<u32>() * 3;
    let gid = read_u32(&buffer, cursor)?;
    Ok((pid, uid, gid))
}

fn read_u32(buffer: &[u8], offset: usize) -> Result<u32> {
    let bytes = buffer
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| Error::new(EINVAL))?;

    Ok(u32::from_le_bytes(bytes))
}
