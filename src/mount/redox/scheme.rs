use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::{Cursor, Seek};
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use libredox::call::MmapArgs;
use redox_scheme::{CallerCtx, OpenResult, SchemeMut};
use slab::Slab;

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
use syscall::{
    MunmapFlags, EBADFD, EOVERFLOW, MODE_PERM, O_APPEND, PAGE_SIZE, PROT_EXEC, PROT_READ,
    PROT_WRITE,
};

use redox_path::{
    canonicalize_to_standard, canonicalize_using_cwd, canonicalize_using_scheme, scheme_path,
    RedoxPath,
};

use crate::mount::redox::resource::{FileMmapInfo, InodeKind};
use crate::{Disk, FileSystem, Node, Transaction, TreeData, TreePtr, BLOCK_SIZE};

use super::resource::{Fmap, InodeInfo, InodeKey};

#[derive(Clone)]
struct OpenHandle {
    inode: TreePtr<Node>,
    path: String,
    flags: usize,
    uid: u32,
    kind: HandleKind,
}
#[derive(Clone)]
enum HandleKind {
    File,
    Directory {
        // TODO: remove, instead this should be fetched directly using a getdents-like syscall
        data: Box<[u8]>,
    },
}

pub struct FileScheme<D: Disk> {
    name: String,
    pub(crate) fs: FileSystem<D>,
    handles: Slab<OpenHandle>,
    inodes: HashMap<InodeKey, InodeInfo>,
}

impl<D: Disk> FileScheme<D> {
    pub fn new(name: String, fs: FileSystem<D>) -> FileScheme<D> {
        FileScheme {
            name,
            fs,
            handles: Slab::new(),
            inodes: HashMap::new(),
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
    fn add_inode_ref(
        &mut self,
        node_ptr: TreePtr<Node>,
        parent_ptr_opt: Option<TreePtr<Node>>,
    ) -> Result<()> {
        match self.inodes.entry(InodeKey(node_ptr)) {
            Entry::Occupied(mut occupied) => {
                let rc = &mut occupied.get_mut().open_handles;
                *rc = rc.checked_add(1).ok_or(Error::new(EOVERFLOW))?;
            }
            Entry::Vacant(vacant) => {
                vacant.insert(InodeInfo {
                    parent_ptr_opt,
                    kind: InodeKind::File {
                        mmaps: FileMmapInfo::default(),
                    },
                    open_handles: 1,
                });
            }
        }
        Ok(())
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
        let existing_node_opt = self
            .fs
            .tx(|tx| Self::path_nodes(scheme_name, tx, path, uid, gid, &mut nodes))?;
        let parent_ptr_opt = nodes.last().map(|x| x.0.ptr());

        let new_handle: OpenHandle = match existing_node_opt {
            Some((node, _node_name)) => {
                if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
                    return Err(Error::new(EEXIST));
                }
                if node.data().is_dir() {
                    if flags & O_WRONLY != 0 {
                        // println!("{:X} & {:X}: EISDIR {}", flags, O_DIRECTORY, path);
                        return Err(Error::new(EISDIR));
                    }
                    let mut data = Vec::new();
                    if flags & O_ACCMODE == O_RDONLY {
                        if !node.data().permission(uid, gid, Node::MODE_READ) {
                            // println!("dir not readable {:o}", node.data().mode);
                            return Err(Error::new(EACCES));
                        }

                        let mut children = Vec::new();
                        self.fs.tx(|tx| tx.child_nodes(node.ptr(), &mut children))?;

                        for child in children.iter() {
                            if let Some(child_name) = child.name() {
                                if !data.is_empty() {
                                    data.push(b'\n');
                                }
                                data.extend_from_slice(&child_name.as_bytes());
                            }
                        }
                    }
                    self.add_inode_ref(node.ptr(), parent_ptr_opt)?;

                    OpenHandle {
                        inode: node.ptr(),
                        flags,
                        uid,
                        path: path.to_owned(),
                        kind: HandleKind::Directory {
                            data: data.into_boxed_slice(),
                        },
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
                            tx.truncate_node(node.ptr(), 0, mtime.as_secs(), mtime.subsec_nanos())
                        })?;
                    }

                    self.add_inode_ref(node.ptr(), parent_ptr_opt)?;

                    OpenHandle {
                        inode: node.ptr(),
                        path: path.to_owned(),
                        kind: HandleKind::File,
                        flags,
                        uid,
                    }
                }
            }
            None => {
                if flags & O_CREAT != O_CREAT {
                    return Err(Error::new(ENOENT));
                }
                let last_part = path
                    .split('/')
                    .rfind(|part| !part.is_empty())
                    .ok_or(Error::new(EPERM))?;
                let (parent, _parent_name) = nodes.last().ok_or(Error::new(EPERM))?;

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

                let prev = self.inodes.insert(
                    InodeKey(node_ptr),
                    InodeInfo {
                        parent_ptr_opt,
                        kind: if dir {
                            InodeKind::Dir
                        } else {
                            InodeKind::File {
                                mmaps: FileMmapInfo::default(),
                            }
                        },
                        open_handles: 1,
                    },
                );
                assert!(prev.is_none(), "newly created inode already inserted");

                OpenHandle {
                    inode: node_ptr,
                    path: path.to_owned(),
                    flags,
                    uid,
                    kind: if dir {
                        HandleKind::Directory { data: Box::new([]) }
                    } else {
                        HandleKind::File
                    },
                }
            }
        };

        Ok(OpenResult::ThisScheme {
            number: self.handles.insert(new_handle),
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
    fn dup(&mut self, old_id: usize, buf: &[u8]) -> Result<usize> {
        // println!("Dup {}", old_id);

        if !buf.is_empty() {
            return Err(Error::new(EINVAL));
        }

        let old_handle = &self.handles[old_id];
        let new_handle = old_handle.clone();

        let inode = self
            .inodes
            .get_mut(&InodeKey(old_handle.inode))
            .ok_or(Error::new(EBADF))?;
        inode.open_handles = inode
            .open_handles
            .checked_add(1)
            .ok_or(Error::new(EOVERFLOW))?;

        Ok(self.handles.insert(new_handle))
    }

    fn read(&mut self, id: usize, buf: &mut [u8], offset: u64, _fcntl_flags: u32) -> Result<usize> {
        let handle = &self.handles[id];
        if handle.flags & O_ACCMODE != O_RDWR && handle.flags & O_ACCMODE != O_RDONLY {
            return Err(Error::new(EBADF));
        }

        // println!("Read {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        match handle.kind {
            HandleKind::Directory { ref data } => {
                let src_buf = usize::try_from(offset)
                    .ok()
                    .and_then(|o| data.get(o..))
                    .unwrap_or(&[]);
                let bytes = buf.len().min(src_buf.len());
                buf[..bytes].copy_from_slice(&src_buf[..bytes]);
                Ok(bytes)
            }
            HandleKind::File => self.fs.tx(|tx| {
                let atime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                tx.read_node(
                    handle.inode,
                    offset,
                    buf,
                    atime.as_secs(),
                    atime.subsec_nanos(),
                )
            }),
        }
    }

    fn write(&mut self, id: usize, buf: &[u8], offset: u64, _fcntl_flags: u32) -> Result<usize> {
        let handle = &self.handles[id];

        if handle.flags & O_ACCMODE != O_RDWR && handle.flags & O_ACCMODE != O_WRONLY {
            return Err(Error::new(EBADF));
        }
        if !matches!(handle.kind, HandleKind::File) {
            // Can't write data to directories.
            return Err(Error::new(EBADF));
        };

        // println!("Write {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());
        self.fs.tx(|tx| {
            let effective_offset = if handle.flags & O_APPEND == O_APPEND {
                let node = tx.read_tree(handle.inode)?;
                node.data().size()
            } else {
                offset
            };
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            tx.write_node(
                handle.inode,
                effective_offset,
                buf,
                mtime.as_secs(),
                mtime.subsec_nanos(),
            )
        })
    }

    fn fsize(&mut self, id: usize) -> Result<u64> {
        let handle = &self.handles[id];

        // println!("Fsize {}", id);
        match handle.kind {
            HandleKind::Directory { ref data } => Ok(data.len().try_into().unwrap()),
            HandleKind::File => self
                .fs
                .tx(|tx| Ok(tx.read_tree(self.handles[id].inode)?.data().size())),
        }
    }

    fn fchmod(&mut self, id: usize, mode: u16) -> Result<usize> {
        let handle = &self.handles[id];

        self.fs.tx(|tx| {
            let mut node = tx.read_tree(handle.inode)?;

            if node.data().uid() != handle.uid && handle.uid != 0 {
                return Err(Error::new(EPERM));
            }
            let old_mode = node.data().mode();
            let new_mode = (old_mode & !MODE_PERM) | (mode & MODE_PERM);
            if old_mode != new_mode {
                node.data_mut().set_mode(new_mode);
                tx.sync_tree(node)?;
            }

            Ok(0)
        })
    }

    fn fchown(&mut self, id: usize, uid: u32, gid: u32) -> Result<usize> {
        let handle = &self.handles[id];

        self.fs.tx(|tx| {
            let mut node = tx.read_tree(handle.inode)?;

            let old_uid = node.data().uid();
            if old_uid != handle.uid && handle.uid != 0 {
                return Err(Error::new(EPERM));
            }
            let mut node_changed = false;

            if uid as i32 != -1 {
                if uid != old_uid {
                    node.data_mut().set_uid(uid);
                    node_changed = true;
                }
            }

            if gid as i32 != -1 {
                let old_gid = node.data().gid();
                if gid != old_gid {
                    node.data_mut().set_gid(gid);
                    node_changed = true;
                }
            }

            if node_changed {
                tx.sync_tree(node)?;
            }

            Ok(0)
        })
    }

    fn fevent(&mut self, _id: usize, _flags: EventFlags) -> Result<EventFlags> {
        // EPERM is returned for files that are always readable or writable
        Err(Error::new(EPERM))
    }

    fn fpath(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        use std::io::Write;

        // println!("Fpath {}, {:X} {}", id, buf.as_ptr() as usize, buf.len());

        let mut dst = Cursor::new(buf);
        if write!(dst, "/scheme/{}/", self.name).is_ok() {
            let _ = write!(dst, "{}", self.handles[id].path);
        }

        Ok(dst.stream_position().unwrap().try_into().unwrap())
    }

    //TODO: this function has too much code, try to simplify it
    fn frename(&mut self, id: usize, url: &str, uid: u32, gid: u32) -> Result<usize> {
        let new_path = url.trim_matches('/');

        // println!("Frename {}, {} from {}, {}", id, new_path, uid, gid);

        let file = &mut self.handles[id];
        let inode = file.inode;
        let inode_info = self
            .inodes
            .get(&InodeKey(inode))
            .ok_or(Error::new(EBADFD))?;

        //TODO: Check for EINVAL
        // The new pathname contained a path prefix of the old, or, more generally,
        // an attempt was made to make a directory a subdirectory of itself.

        let old_name = file
            .path
            .split('/')
            .rfind(|part| !part.is_empty())
            .ok_or(Error::new(EPERM))?
            .to_owned();
        let new_name = new_path
            .split('/')
            .rfind(|part| !part.is_empty())
            .ok_or(Error::new(EPERM))?;

        let scheme_name = &self.name;

        self.fs.tx(|tx| {
            // Can't remove root
            let orig_parent_ptr = inode_info.parent_ptr_opt.ok_or(Error::new(EBUSY))?;

            let orig_node = tx.read_tree(inode)?;

            if !orig_node.data().owner(uid) {
                // println!("orig_node not owned by caller {}", uid);
                return Err(Error::new(EACCES));
            }

            let mut new_nodes = Vec::new();
            let new_node_opt =
                Self::path_nodes(scheme_name, tx, new_path, uid, gid, &mut new_nodes)?;

            let (ref new_parent, _) = new_nodes.last().ok_or(Error::new(EPERM))?;
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

            file.path = new_path.to_owned();
            Ok(0)
        })
    }

    fn fstat(&mut self, id: usize, stat: &mut Stat) -> Result<usize> {
        let handle = &self.handles[id];

        // println!("Fstat {}, {:X}", id, stat as *mut Stat as usize);
        self.fs.tx(|tx| {
            let node = tx.read_tree(handle.inode)?;

            let ctime = node.data().ctime();
            let mtime = node.data().mtime();
            let atime = node.data().atime();
            *stat = Stat {
                st_dev: 0, // TODO
                st_ino: node.id() as u64,
                st_mode: node.data().mode(),
                st_nlink: node.data().links(),
                st_uid: node.data().uid(),
                st_gid: node.data().gid(),
                st_size: node.data().size(),
                st_mtime: mtime.0,
                st_mtime_nsec: mtime.1,
                st_atime: atime.0,
                st_atime_nsec: atime.1,
                st_ctime: ctime.0,
                st_ctime_nsec: ctime.1,
                ..Default::default()
            };

            Ok(0)
        })
    }

    fn fstatvfs(&mut self, _id: usize, stat: &mut StatVfs) -> Result<usize> {
        stat.f_bsize = BLOCK_SIZE as u32;
        stat.f_blocks = self.fs.header.size() / (stat.f_bsize as u64);
        stat.f_bfree = self.fs.allocator().free();
        stat.f_bavail = stat.f_bfree;

        Ok(0)
    }

    fn fsync(&mut self, id: usize) -> Result<usize> {
        let handle = &self.handles[id];
        let InodeInfo {
            kind: InodeKind::File { mmaps },
            ..
        } = self
            .inodes
            .get_mut(&InodeKey(handle.inode))
            .ok_or(Error::new(EBADFD))?
        else {
            return Ok(0);
        };

        // println!("Fsync {}", id);
        self.fs.tx(|tx| {
            unsafe {
                mmaps.msync(handle.inode, tx)?;
            }
            Ok(())
        })?;

        Ok(0)
    }

    fn ftruncate(&mut self, id: usize, len: usize) -> Result<usize> {
        let handle = &self.handles[id];

        if handle.flags & O_ACCMODE != O_RDWR && handle.flags & O_ACCMODE != O_WRONLY {
            return Err(Error::new(EBADF));
        }

        // println!("Ftruncate {}, {}", id, len);
        self.fs.tx(|tx| {
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            tx.truncate_node(
                handle.inode,
                len as u64,
                mtime.as_secs(),
                mtime.subsec_nanos(),
            )?;
            Ok(0)
        })
    }

    fn futimens(&mut self, id: usize, times: &[TimeSpec]) -> Result<usize> {
        let handle = &self.handles[id];

        // println!("Futimens {}, {}", id, times.len());
        self.fs.tx(|tx| {
            let mut node = tx.read_tree(handle.inode)?;

            if node.data().uid() != handle.uid && handle.uid != 0 {
                return Err(Error::new(EPERM));
            }
            if let &[atime, mtime] = times {
                let mut node_changed = false;

                let old_mtime = node.data().mtime();
                let new_mtime = (mtime.tv_sec as u64, mtime.tv_nsec as u32);
                if old_mtime != new_mtime {
                    node.data_mut().set_mtime(new_mtime.0, new_mtime.1);
                    node_changed = true;
                }

                let old_atime = node.data().atime();
                let new_atime = (atime.tv_sec as u64, atime.tv_nsec as u32);
                if old_atime != new_atime {
                    node.data_mut().set_atime(new_atime.0, new_atime.1);
                    node_changed = true;
                }

                if node_changed {
                    tx.sync_tree(node)?;
                }
            }
            Ok(0)
        })
    }

    fn mmap_prep(
        &mut self,
        id: usize,
        offset: u64,
        unaligned_size: usize,
        flags: MapFlags,
    ) -> Result<usize> {
        let handle = &self.handles[id];
        let InodeInfo {
            kind: InodeKind::File { mmaps },
            ..
        } = self
            .inodes
            .get_mut(&InodeKey(handle.inode))
            .ok_or(Error::new(EBADFD))?
        else {
            // can't mmap directories
            return Err(Error::new(EBADF));
        };

        let accmode = handle.flags & O_ACCMODE;

        // PROT_EXEC is equivalent to PROT_READ in this case
        if (flags.contains(PROT_READ) || flags.contains(PROT_EXEC))
            && !(accmode == O_RDWR || accmode == O_RDONLY)
        {
            return Err(Error::new(EBADF));
        }
        if flags.contains(PROT_WRITE) && !(accmode == O_RDWR || accmode == O_WRONLY) {
            return Err(Error::new(EBADF));
        }
        if offset % u64::try_from(PAGE_SIZE).unwrap() != 0 {
            return Err(Error::new(EINVAL));
        }

        self.fs.tx(|tx| {
            let aligned_size = unaligned_size.next_multiple_of(PAGE_SIZE);

            let new_size = (offset as usize + aligned_size).next_multiple_of(PAGE_SIZE);
            if new_size > mmaps.size {
                mmaps.base = if mmaps.base.is_null() {
                    unsafe {
                        libredox::call::mmap(MmapArgs {
                            length: new_size,
                            // PRIVATE/SHARED doesn't matter once the pages are passed in the fmap
                            // handler.
                            prot: libredox::flag::PROT_READ | libredox::flag::PROT_WRITE,
                            flags: libredox::flag::MAP_PRIVATE,

                            offset: 0,
                            fd: !0,
                            addr: core::ptr::null_mut(),
                        })? as *mut u8
                    }
                } else {
                    unsafe {
                        syscall::syscall5(
                            syscall::SYS_MREMAP,
                            mmaps.base as usize,
                            mmaps.size,
                            0,
                            new_size,
                            syscall::MremapFlags::empty().bits() | (PROT_READ | PROT_WRITE).bits(),
                        )? as *mut u8
                    }
                };
                mmaps.size = new_size;
            }

            let affected_fmaps = mmaps
                .ranges
                .remove_and_unused(offset..offset + aligned_size as u64);

            for (range, v_opt) in affected_fmaps {
                //dbg!(&range);
                if let Some(mut fmap) = v_opt {
                    fmap.rc += 1;
                    fmap.flags |= flags;

                    let _ = mmaps
                        .ranges
                        .insert(range.start, range.end - range.start, fmap);
                } else {
                    let map = unsafe {
                        Fmap::new(handle.inode, flags, unaligned_size, offset, mmaps.base, tx)?
                    };
                    let _ = mmaps.ranges.insert(offset, aligned_size as u64, map);
                }
            }

            Ok(mmaps.base as usize + offset as usize)
        })
    }
    fn munmap(
        &mut self,
        id: usize,
        offset: u64,
        size: usize,
        _flags: MunmapFlags,
    ) -> Result<usize> {
        let handle = &self.handles[id];
        let InodeInfo {
            kind: InodeKind::File { mmaps },
            ..
        } = self
            .inodes
            .get_mut(&InodeKey(handle.inode))
            .ok_or(Error::new(EBADFD))?
        else {
            return Err(Error::new(EBADF));
        };

        self.fs.tx(|tx| {
            unsafe {
                mmaps.munmap(handle.inode, offset, size, tx)?;
            }
            Ok(0)
        })
    }

    fn close(&mut self, id: usize) -> Result<usize> {
        // println!("Close {}", id);
        let file = self.handles.remove(id);

        let inode = self
            .inodes
            .get_mut(&InodeKey(file.inode))
            .ok_or(Error::new(EBADFD))?;
        inode.open_handles = inode
            .open_handles
            .checked_sub(1)
            .expect("inode refcount underflow");

        if !inode.has_refs() {
            // TODO: currently no cached data, but when impld, it should be flushed
            self.inodes.remove(&InodeKey(file.inode));
        }

        // TODO: Remove file if open_handles and nlink are 0 and `mmaps` is empty

        Ok(0)
    }
}
