use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::mem;
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use async_lock::{MutexGuardArc, RwLock};
use libredox::Fd;
use redox_path::RedoxReference;
use redox_path::RedoxScheme;
use redox_path::RedoxStr;
use redox_scheme::{scheme::SchemeAsync, CallerCtx, OpenResult, SendFdRequest, Socket};
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

use crate::{
    transaction::TransactionRead, Disk, FileSystem, Node, Transaction, TreeData, TreePtr,
    BLOCK_SIZE,
};

use super::async_map::AsyncMap;
use super::resource::{DirResource, Entry, FileMmapInfo, FileResource, BaseResource, Resource};

enum Handle<D: Disk> {
    ResourceDir((DirResource, PhantomData<D>)),
    ResourceFile((FileResource, PhantomData<D>)),
    SchemeRoot,
}

impl<D: Disk> Handle<D> {
    fn resource<'a>(&'a mut self) -> Result<HandleMutRef<'a, D>> {
        match self {
            Handle::ResourceDir((dir, _)) => {
                Ok(HandleMutRef::RefDir((dir as &mut DirResource, PhantomData)))
            }
            Handle::ResourceFile((file, _)) => Ok(HandleMutRef::RefFile((
                file as &mut FileResource,
                PhantomData,
            ))),
            Handle::SchemeRoot => Err(Error::new(EBADF)),
        }
    }

    fn make_path<'a>(&self, path: RedoxReference<'a>) -> Result<RedoxReference<'a>> {
        Ok(match self {
            Handle::ResourceDir((dir, _)) if path.is_relative() => RedoxReference::new(&dir.base.path)
                .ok_or(Error::new(ENOENT))?
                .join_checked(path),
            Handle::ResourceFile(_) => return Err(Error::new(ENOTDIR)),
            _ => path,
        }
        .canonical())
    }
}

// dyn and async don't play well together, so this is a workaround
// for acquiring a generic Resource

enum HandleMutRef<'a, D: Disk> {
    RefDir((&'a mut DirResource, PhantomData<D>)),
    RefFile((&'a mut FileResource, PhantomData<D>)),
}

impl<'r, D: Disk> HandleMutRef<'r, D> {
    // This lets us avoid exporting a base_mut() implementation.
    fn set_path(&mut self, path: &str) {
        match self {
            HandleMutRef::RefDir(dir) => dir.0.base.path = path.to_string(),
            HandleMutRef::RefFile(file) => file.0.base.path = path.to_string(),
        };
    }
}

impl<'r, D: Disk> Resource<D> for HandleMutRef<'r, D> {

    fn base(&self) -> &BaseResource {
        match self {
            HandleMutRef::RefDir(dir) => &dir.0.base,
            HandleMutRef::RefFile(file) => &file.0.base,
        }
    }

    async fn read<'a>(
        &mut self,
        fmaps: &super::resource::Fmaps,
        buf: &mut [u8],
        offset: u64,
        tx: &mut TransactionRead<'a, D>,
    ) -> Result<usize> {
        match self {
            HandleMutRef::RefDir(dir) => dir.0.read(fmaps, buf, offset, tx).await,
            HandleMutRef::RefFile(file) => file.0.read(fmaps, buf, offset, tx).await,
        }
    }

    async fn write<'a>(
        &mut self,
        fmaps: &super::resource::Fmaps,
        buf: &[u8],
        offset: u64,
        tx: &mut Transaction<'a, D>,
    ) -> Result<usize> {
        match self {
            HandleMutRef::RefDir(dir) => dir.0.write(fmaps, buf, offset, tx).await,
            HandleMutRef::RefFile(file) => file.0.write(fmaps, buf, offset, tx).await,
        }
    }

    async fn fsize<'a>(&mut self, tx: &mut TransactionRead<'a, D>) -> Result<u64> {
        match self {
            HandleMutRef::RefDir(dir) => dir.0.fsize(tx).await,
            HandleMutRef::RefFile(file) => file.0.fsize(tx).await,
        }
    }

    async fn fmap<'a>(
        &mut self,
        fmaps: &super::resource::Fmaps,
        flags: MapFlags,
        size: usize,
        offset: u64,
        tx: &mut Transaction<'a, D>,
    ) -> Result<usize> {
        match self {
            HandleMutRef::RefDir(dir) => dir.0.fmap(fmaps, flags, size, offset, tx).await,
            HandleMutRef::RefFile(file) => file.0.fmap(fmaps, flags, size, offset, tx).await,
        }
    }

    async fn funmap<'a>(
        &mut self,
        fmaps: &super::resource::Fmaps,
        offset: u64,
        size: usize,
        tx: &mut Transaction<'a, D>,
    ) -> Result<()> {
        match self {
            HandleMutRef::RefDir(dir) => dir.0.funmap(fmaps, offset, size, tx).await,
            HandleMutRef::RefFile(file) => file.0.funmap(fmaps, offset, size, tx).await,
        }
    }

    // Both DirResource and FileResource use the default fchmod(), fchown() and stat().

    fn fcntl<'a>(
        &mut self,
        cmd: usize,
        arg: usize,
        ph: PhantomData<D>,
    ) -> Result<usize> {
        match self {
            HandleMutRef::RefDir(dir) => dir.0.fcntl(cmd, arg, ph),
            HandleMutRef::RefFile(file) => file.0.fcntl(cmd, arg, ph),
        }
    }

    async fn sync<'a>(
        &mut self,
        fmaps: &super::resource::Fmaps,
        tx: &mut Transaction<'a, D>,
    ) -> Result<()> {
        match self {
            HandleMutRef::RefDir(dir) => dir.0.sync(fmaps, tx).await,
            HandleMutRef::RefFile(file) => file.0.sync(fmaps, tx).await,
        }
    }

    async fn truncate<'a>(&mut self, len: u64, tx: &mut Transaction<'a, D>) -> Result<()> {
        match self {
            HandleMutRef::RefDir(dir) => dir.0.truncate(len, tx).await,
            HandleMutRef::RefFile(file) => file.0.truncate(len, tx).await,
        }
    }

    async fn utimens<'a>(&mut self, times: &[TimeSpec], tx: &mut Transaction<'a, D>) -> Result<()> {
        match self {
            HandleMutRef::RefDir(dir) => dir.0.utimens(times, tx).await,
            HandleMutRef::RefFile(file) => file.0.utimens(times, tx).await,
        }
    }

    async fn getdents<'a, 'buf>(
        &mut self,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
        tx: &mut TransactionRead<'a, D>,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        match self {
            HandleMutRef::RefDir(dir) => dir.0.getdents(buf, opaque_offset, tx).await,
            HandleMutRef::RefFile(file) => file.0.getdents(buf, opaque_offset, tx).await,
        }
    }
}

// Lock order is handles, fmap, fs, other_scheme_fd_map

pub struct FileScheme<'sock, D: Disk> {
    scheme_name: RedoxScheme<'sock>,
    mounted_path: String,
    pub(crate) fs: RwLock<FileSystem<D>>,
    socket: &'sock Socket,
    next_id: AtomicUsize,
    handles: AsyncMap<usize, Handle<D>>,
    fmap: super::resource::Fmaps,

    // Map of file id to other scheme's file descriptor.
    other_scheme_fd_map: RwLock<BTreeMap<u32, Fd>>,

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
            fs: RwLock::new(fs),
            socket: socket,
            next_id: AtomicUsize::new(1),
            handles: AsyncMap::new(),
            fmap: AsyncMap::new(),
            other_scheme_fd_map: RwLock::new(BTreeMap::new()),
            proc_creds_capability: {
                libredox::Fd::open(
                    "/scheme/proc/proc-creds-capability",
                    libredox::flag::O_RDONLY,
                    0,
                )?
            },
        })
    }

    async fn get_handle(&self, id: usize) -> Result<MutexGuardArc<Handle<D>>> {
        self.handles.get(&id).await.ok_or(Error::new(EBADF))
    }

    pub async fn tx_read<F: AsyncFnOnce(&mut TransactionRead<D>) -> Result<T>, T>(
        &self,
        f: F,
    ) -> Result<T> {
        self.fs.read().await.tx_read(f).await
    }

    pub async fn tx<F: AsyncFnOnce(&mut Transaction<D>) -> Result<T>, T>(&self, f: F) -> Result<T> {
        self.fs.write().await.tx(f).await
    }

    /// Resolve a symbolic link of given `node`. `full_path` must be non-canonicalized path from root node.
    async fn resolve_symlink<'a, 'b>(
        scheme_name: &RedoxScheme<'sock>,
        tx: &mut Transaction<'b, D>,
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
            let count = tx
                .read_node(
                    node.ptr(),
                    0,
                    &mut buf,
                    atime.as_secs(),
                    atime.subsec_nanos(),
                )
                .await?;

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
                RedoxStr::Relative(redox_reference) => {
                    working_dir.join_checked(redox_reference).canonical()
                }
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
            )
            .await?
            {
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

    async fn handle_connect(&self, id: usize, payload: &mut [u8]) -> Result<usize> {
        let mut hdl = self.get_handle(id).await?;
        let resource = hdl.resource()?;
        let inode_id = resource.base().node_ptr.id();
        let fd_map = self.other_scheme_fd_map.read().await;
        let target_fd = fd_map.get(&inode_id).ok_or(Error::new(EBADF))?;
        let len = libredox::call::get_socket_token(target_fd.raw(), payload)?;
        return Ok(len);
    }

    async fn open(
        &self,
        url: RedoxReference<'_>,
        flags: usize,
        ctx: &CallerCtx,
    ) -> Result<OpenResult> {
        self.open_internal(TreePtr::root(), url, flags, ctx).await
    }

    async fn open_internal(
        &self,
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
            .tx(async |tx| {
                Self::path_nodes(scheme_name, tx, start_ptr, &path, uid, gid, &mut nodes).await
            })
            .await?;
        let parent_ptr_opt = nodes.last().map(|x| x.0.ptr());
        let mut handle: Handle<D> = match node_opt {
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
                        self.tx(async |tx| tx.child_nodes(node.ptr(), &mut children).await)
                            .await?;

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
                    let resolved = self
                        .tx(async |tx| {
                            Self::resolve_symlink(
                                scheme_name,
                                tx,
                                uid,
                                gid,
                                path,
                                node,
                                &mut resolve_nodes,
                            )
                            .await
                        })
                        .await?;
                    return Box::pin(self.open(resolved, flags, ctx)).await;
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
                        self.tx(async |tx| {
                            tx.truncate_node(node_ptr, 0, mtime.as_secs(), mtime.subsec_nanos())
                                .await
                        })
                        .await?;
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

                let node_ptr = self
                    .tx(async |tx| {
                        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                        let mut node = tx
                            .create_node(
                                parent.ptr(),
                                &last_part,
                                mode_type as u16 | (flags as u16 & Node::MODE_PERM),
                                ctime.as_secs(),
                                ctime.subsec_nanos(),
                            )
                            .await?;
                        let node_ptr = node.ptr();
                        if node.data().uid() != uid || node.data().gid() != gid {
                            node.data_mut().set_uid(uid);
                            node.data_mut().set_gid(gid);
                            tx.sync_tree(node).await?;
                        }
                        Ok(node_ptr)
                    })
                    .await?;

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

        let node_ptr = handle.resource().unwrap().base().node_ptr;
        {
            let mut fmap_info = self
                .fmap
                .get_or_insert_with(node_ptr.id(), FileMmapInfo::new)
                .await;
            if !fmap_info.in_use() {
                // Notify filesystem of open
                self.tx(async |tx| tx.on_open_node(node_ptr)).await?;
            }
            fmap_info.open_fds += 1;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles.insert(id, handle).await;

        Ok(OpenResult::ThisScheme {
            number: id,
            flags: NewFdFlags::POSITIONED,
        })
    }

    async fn unlink_internal(
        &self,
        start_ptr: TreePtr<Node>,
        path: &RedoxReference<'_>,
        flags: usize,
        uid: u32,
        gid: u32,
    ) -> Result<()> {
        let scheme_name = &self.scheme_name;

        let unlink_result = self
            .tx(async |tx| {
                let mut nodes = SmallVec::new();

                let Some((child, child_name)) =
                    Self::path_nodes(scheme_name, tx, start_ptr, path, uid, gid, &mut nodes)
                        .await?
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
                            .await
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

                        tx.remove_node(parent.ptr(), &child_name, mode).await
                    } else {
                        Err(Error::new(EISDIR))
                    }
                }
            })
            .await;

        let Some(node_id) = unlink_result? else {
            return Ok(());
        };

        let _ = self.other_scheme_fd_map.write().await.remove(&node_id);

        Ok(())
    }

    async fn path_nodes<'a>(
        scheme_name: &RedoxScheme<'sock>,
        tx: &mut Transaction<'a, D>,
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
                None => tx.read_tree(node_ptr).await,
                Some(part) => {
                    node_name = part.to_string();
                    tx.find_node(node_ptr, part).await
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
                    Box::pin(Self::resolve_symlink(
                        scheme_name,
                        tx,
                        uid,
                        gid,
                        url,
                        node,
                        nodes,
                    ))
                    .await?;
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

impl<'sock, D: Disk> SchemeAsync for FileScheme<'sock, D> {
    fn scheme_root(&mut self) -> Result<usize> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles.insert_mut(id, Handle::SchemeRoot);
        Ok(id)
    }

    async fn openat(
        &self,
        dirfd: usize,
        path: &str,
        flags: usize,
        _fcntl_flags: u32,
        ctx: &CallerCtx,
    ) -> Result<OpenResult> {
        let path = RedoxReference::new(path).ok_or(Error::new(EINVAL))?;
        let path_to_open = self.get_handle(dirfd).await?.make_path(path)?;
        self.open_internal(TreePtr::root(), path_to_open.to_relative(), flags, ctx)
            .await
    }

    async fn unlinkat(
        &self,
        dirfd: usize,
        path: &str,
        flags: usize,
        ctx: &CallerCtx,
    ) -> Result<()> {
        let uid = ctx.uid;
        let gid = ctx.gid;
        let path = RedoxReference::new(path).ok_or(Error::new(EINVAL))?;
        let path_to_unlink = self.get_handle(dirfd).await?.make_path(path)?;
        let start_ptr = TreePtr::root();

        // println!("Unlinkat '{}' flags: {:X}", path, flags);

        self.unlink_internal(start_ptr, &path_to_unlink, flags, uid, gid)
            .await
    }

    /* Resource operations */
    async fn read(
        &self,
        id: usize,
        buf: &mut [u8],
        offset: u64,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        // println!("Read {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        self.tx_read(async |tx| file.read(&self.fmap, buf, offset, tx).await)
            .await
    }

    async fn write(
        &self,
        id: usize,
        buf: &[u8],
        offset: u64,
        _fcntl_flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        // println!("Write {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        self.tx(async |tx| file.write(&self.fmap, buf, offset, tx).await)
            .await
    }

    async fn fsize(&self, id: usize, _ctx: &CallerCtx) -> Result<u64> {
        // println!("Seek {}, {} {}", id, pos, whence);
        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        self.tx_read(async |tx| file.fsize(tx).await).await
    }

    async fn fchmod(&self, id: usize, mode: u16, _ctx: &CallerCtx) -> Result<()> {
        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        self.tx(async |tx| file.fchmod(mode, tx).await).await
    }

    async fn fchown(&self, id: usize, new_uid: u32, new_gid: u32, _ctx: &CallerCtx) -> Result<()> {
        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        self.tx(async |tx| file.fchown(new_uid, new_gid, tx).await)
            .await
    }

    async fn fcntl(&self, id: usize, cmd: usize, arg: usize, _ctx: &CallerCtx) -> Result<usize> {
        self.get_handle(id).await?.resource()?.fcntl(cmd, arg, PhantomData::<D>)
    }

    async fn fevent(&self, id: usize, _flags: EventFlags, _ctx: &CallerCtx) -> Result<EventFlags> {
        let _file = self.get_handle(id).await?.resource()?;
        // EPERM is returned for handles that are always readable or writable
        Err(Error::new(EPERM))
    }

    async fn fpath(&self, id: usize, buf: &mut [u8], _ctx: &CallerCtx) -> Result<usize> {
        // println!("Fpath {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        let mut hdl = self.get_handle(id).await?;
        let file = hdl.resource()?;
        let mounted_path = self.mounted_path.as_bytes();

        let mut i = 0;
        while i < buf.len() && i < mounted_path.len() {
            buf[i] = mounted_path[i];
            i += 1;
        }

        let path = file.base().path.as_bytes();
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
    async fn flink(&self, id: usize, url: &str, ctx: &CallerCtx) -> Result<usize> {
        let new_path = RedoxReference::new(url)
            .ok_or(Error::new(EINVAL))?
            .canonical();
        let uid = ctx.uid;
        let gid = ctx.gid;

        // println!("Flink {}, {} from {}, {}", id, new_path, uid, gid);

        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        //TODO: Check for EINVAL
        // The new pathname contained a path prefix of the old, or, more generally,
        // an attempt was made to make a directory a subdirectory of itself.

        let mut old_name = String::new();
        for part in file.base().path.split('/') {
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
        self.tx(async |tx| {
            let _orig_parent_ptr = match file.base().parent_ptr_opt {
                Some(some) => some,
                None => {
                    // println!("orig is root");
                    return Err(Error::new(EBUSY));
                }
            };

            let orig_node = tx.read_tree(file.base().node_ptr).await?;

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
            )
            .await?;

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
                        tx.child_nodes(new_node.ptr(), &mut children).await?;

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

                tx.link_node(new_parent.ptr(), &new_name, orig_node.ptr())
                    .await?;

                file.set_path(new_path.as_ref());
                Ok(0)
            } else {
                Err(Error::new(EPERM))
            }
        })
        .await
    }

    //TODO: this function has too much code, try to simplify it
    async fn frename(&self, id: usize, url: &str, ctx: &CallerCtx) -> Result<usize> {
        let new_path = RedoxReference::new(url)
            .ok_or(Error::new(EINVAL))?
            .canonical();
        let uid = ctx.uid;
        let gid = ctx.gid;

        // println!("Frename {}, {} from {}, {}", id, new_path, uid, gid);

        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        //TODO: Check for EINVAL
        // The new pathname contained a path prefix of the old, or, more generally,
        // an attempt was made to make a directory a subdirectory of itself.

        let mut old_name = String::new();
        for part in file.base().path.split('/') {
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
        self.tx(async |tx| {
            let orig_parent_ptr = match file.base().parent_ptr_opt {
                Some(some) => some,
                None => {
                    // println!("orig is root");
                    return Err(Error::new(EBUSY));
                }
            };

            let orig_node = tx.read_tree(file.base().node_ptr).await?;

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
            )
            .await?;

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
                        tx.child_nodes(new_node.ptr(), &mut children).await?;

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

                tx.rename_node(orig_parent_ptr, &old_name, new_parent.ptr(), &new_name)
                    .await?;

                file.set_path(new_path.as_ref());
                Ok(0)
            } else {
                Err(Error::new(EPERM))
            }
        })
        .await
    }

    async fn fstat(&self, id: usize, stat: &mut Stat, _ctx: &CallerCtx) -> Result<()> {
        // println!("Fstat {}, {:X}", id, stat as *mut Stat as usize);
        let mut hdl = self.get_handle(id).await?;
        let file = hdl.resource()?;
        self.tx_read(async |tx| file.stat(stat, tx).await).await
    }

    async fn fstatvfs(&self, id: usize, stat: &mut StatVfs, _ctx: &CallerCtx) -> Result<()> {
        let _file = self.get_handle(id).await?.resource()?;
        let fs = self.fs.read().await;
        stat.f_bsize = BLOCK_SIZE as u32;
        stat.f_blocks = fs.header.size() / (stat.f_bsize as u64);
        stat.f_bfree = fs.allocator().free();
        stat.f_bavail = stat.f_bfree;

        Ok(())
    }

    async fn fsync(&self, id: usize, _ctx: &CallerCtx) -> Result<()> {
        // println!("Fsync {}", id);
        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        self.tx(async |tx| file.sync(&self.fmap, tx).await).await
    }

    async fn ftruncate(&self, id: usize, len: u64, _ctx: &CallerCtx) -> Result<()> {
        // println!("Ftruncate {}, {}", id, len);
        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        self.tx(async |tx| file.truncate(len, tx).await).await
    }

    async fn futimens(&self, id: usize, times: &[TimeSpec], _ctx: &CallerCtx) -> Result<()> {
        // println!("Futimens {}, {}", id, times.len());
        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        self.tx(async |tx| file.utimens(times, tx).await).await
    }

    async fn getdents<'buf>(
        &self,
        id: usize,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        self.tx_read(async |tx| file.getdents(buf, opaque_offset, tx).await)
            .await
    }

    async fn mmap_prep(
        &self,
        id: usize,
        offset: u64,
        size: usize,
        flags: MapFlags,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        self.tx(async |tx| file.fmap(&self.fmap, flags, size, offset, tx).await)
            .await
    }
    async fn munmap(
        &self,
        id: usize,
        offset: u64,
        size: usize,
        _flags: MunmapFlags,
        _ctx: &CallerCtx,
    ) -> Result<()> {
        let mut hdl = self.get_handle(id).await?;
        let mut file = hdl.resource()?;
        self.tx(async |tx| file.funmap(&self.fmap, offset, size, tx).await)
            .await
    }

    async fn on_close(&self, id: usize) {
        // println!("Close {}", id);
        let Some(mut file) = self.handles.remove(&id).await else {
            return;
        };
        let Ok(resource) = file.resource() else {
            return;
        };
        let node_ptr = resource.base().node_ptr;
        let Some(mut file_info) = self.fmap.get_mut(&node_ptr.id()).await else {
            return;
        };

        file_info.open_fds = file_info
            .open_fds
            .checked_sub(1)
            .expect("open_fds not tracked correctly");

        // Check if node no longer in use
        if !file_info.in_use() {
            // Notify filesystem of close
            if let Err(err) = self.tx(async |tx| tx.on_close_node(node_ptr).await).await {
                log::error!("failed to close node {}: {}", node_ptr.id(), err);
            }

            /*TODO: leaks memory, but why?
            // Remove from fmap list
            self.fmap.remove(&node_ptr.id());
            */
        }
    }

    async fn on_sendfd(&self, sendfd_request: &SendFdRequest) -> Result<usize> {
        let ctx = sendfd_request.caller();
        let uid = ctx.uid;
        let gid = ctx.gid;

        let mut hdl = self.get_handle(sendfd_request.id()).await?;
        let parent_resource = hdl.resource()?;

        let mut new_fd = usize::MAX;
        if let Err(e) = sendfd_request.obtain_fd(
            &self.socket,
            FobtainFdFlags::empty(),
            std::slice::from_mut(&mut new_fd),
        ) {
            return Err(e);
        }
        let other_scheme_fd = Fd::new(new_fd);

        let parent_resource_ptr = parent_resource.base().node_ptr;

        let parent_node = self
            .tx(async |tx| tx.read_tree(parent_resource_ptr).await)
            .await?;
        if !parent_node.data().is_dir() {
            return Err(Error::new(ENOTDIR));
        }
        if !parent_node.data().permission(uid, gid, Node::MODE_WRITE) {
            return Err(Error::new(EACCES));
        }
        let parent_path = &parent_resource.base().path;

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
            let node_ptr = self
                .tx(async |tx| {
                    if tx.find_node(parent_resource_ptr, &last_part).await.is_ok() {
                        // If the file already exists, we cannot create it again
                        return Err(Error::new(EEXIST));
                    }

                    let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                    let mut node = tx
                        .create_node(
                            parent_resource_ptr,
                            &last_part,
                            mode_type | (flags as u16 & Node::MODE_PERM),
                            ctime.as_secs(),
                            ctime.subsec_nanos(),
                        )
                        .await?;
                    let node_ptr = node.ptr();
                    if node.data().uid() != uid || node.data().gid() != gid {
                        node.data_mut().set_uid(uid);
                        node.data_mut().set_gid(gid);
                        tx.sync_tree(node).await?;
                    }
                    Ok(node_ptr)
                })
                .await?;

            let file_path = format!("{parent_path}/{last_part}");
            let node_id = node_ptr.id();

            (
                FileResource::new(file_path, Some(parent_resource_ptr), node_ptr, flags, uid),
                node_id,
            )
        };

        let node_ptr = resource.base_no_annot().node_ptr;
        {
            let mut fmap_info = self
                .fmap
                .get_or_insert_with(node_ptr.id(), FileMmapInfo::new)
                .await;
            if !fmap_info.in_use() {
                // Notify filesystem of open
                self.tx(async |tx| tx.on_open_node(node_ptr)).await?;
            }
            fmap_info.open_fds += 1;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles
            .insert(id, Handle::ResourceFile((resource, PhantomData)))
            .await;
        self.other_scheme_fd_map
            .write()
            .await
            .insert(node_id, other_scheme_fd);
        Ok(new_fd)
    }

    async fn call(
        &self,
        id: usize,
        payload: &mut [u8],
        metadata: &[u64],
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        let Some(verb) = FsCall::try_from_raw(metadata[0] as usize) else {
            return Err(Error::new(EINVAL));
        };
        match verb {
            FsCall::Connect => self.handle_connect(id, payload).await,
            _ => Err(Error::new(EOPNOTSUPP)),
        }
    }

    async fn std_fs_call(
        &self,
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
                self.fchown(id, new_uid, new_gid as u32, ctx)
                    .await
                    .map(|_| 0)
            }
            /* TODO: Support Unlinkat using std_fs_call
            Unlinkat => {
                let path = unsafe { str::from_utf8_unchecked(payload) };
                let flags = metadata.arg1;
                let mut hdl = self.get_handle(id).await?;
                let dir_node_ptr = match *hdl {
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

    async fn inode(&self, id: usize) -> Result<usize> {
        Ok(self.get_handle(id).await?.resource()?.base().node_ptr.id() as usize)
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
