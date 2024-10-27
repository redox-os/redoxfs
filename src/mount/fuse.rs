extern crate fuser;

use std::cmp;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use self::fuser::MountOption;
use self::fuser::TimeOrNow;
use crate::mount::fuse::TimeOrNow::Now;
use crate::mount::fuse::TimeOrNow::SpecificTime;

use crate::{filesystem, Disk, Node, Transaction, TreeData, TreePtr, BLOCK_SIZE};

use self::fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyStatfs, ReplyWrite, Request, Session,
};
use std::time::Duration;

const TTL: Duration = Duration::new(1, 0); // 1 second

const NULL_TIME: Duration = Duration::new(0, 0);

pub fn mount<D, P, T, F>(
    mut filesystem: filesystem::FileSystem<D>,
    mountpoint: P,
    callback: F,
) -> io::Result<T>
where
    D: Disk,
    P: AsRef<Path>,
    F: FnOnce(&Path) -> T,
{
    let mountpoint = mountpoint.as_ref();

    // One of the uses of this redoxfs fuse wrapper is to populate a filesystem
    // while building the Redox OS kernel. This means that we need to write on
    // a filesystem that belongs to `root`, which in turn means that we need to
    // be `root`, thus that we need to allow `root` to have access.
    let defer_permissions = [MountOption::CUSTOM("defer_permissions".to_owned())];

    let res = {
        let mut session = Session::new(
            Fuse {
                fs: &mut filesystem,
            },
            mountpoint,
            if cfg!(target_os = "macos") {
                &defer_permissions
            } else {
                &[]
            },
        )?;

        let res = callback(mountpoint);

        session.run()?;

        res
    };

    // Squash allocations and sync on unmount
    let _ = Transaction::new(&mut filesystem).commit(true);

    Ok(res)
}

pub struct Fuse<'f, D: Disk> {
    pub fs: &'f mut filesystem::FileSystem<D>,
}

fn node_attr(node: &TreeData<Node>) -> FileAttr {
    FileAttr {
        ino: node.id() as u64,
        size: node.data().size(),
        // Blocks is in 512 byte blocks, not in our block size
        blocks: (node.data().size() + BLOCK_SIZE - 1) / BLOCK_SIZE * (BLOCK_SIZE / 512),
        blksize: 512,
        atime: SystemTime::UNIX_EPOCH + Duration::new(node.data().atime().0, node.data().atime().1),
        mtime: SystemTime::UNIX_EPOCH + Duration::new(node.data().mtime().0, node.data().mtime().1),
        ctime: SystemTime::UNIX_EPOCH + Duration::new(node.data().ctime().0, node.data().ctime().1),
        crtime: UNIX_EPOCH + NULL_TIME,
        kind: if node.data().is_dir() {
            FileType::Directory
        } else if node.data().is_symlink() {
            FileType::Symlink
        } else {
            FileType::RegularFile
        },
        perm: node.data().mode() & Node::MODE_PERM,
        nlink: node.data().links(),
        uid: node.data().uid(),
        gid: node.data().gid(),
        rdev: 0,
        flags: 0,
    }
}

impl<'f, D: Disk> Filesystem for Fuse<'f, D> {
    fn lookup(&mut self, _req: &Request, parent_id: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_ptr = TreePtr::new(parent_id as u32);
        match self
            .fs
            .tx(|tx| tx.find_node(parent_ptr, name.to_str().unwrap()))
        {
            Ok(node) => {
                reply.entry(&TTL, &node_attr(&node), 0);
            }
            Err(err) => {
                reply.error(err.errno);
            }
        }
    }

    fn getattr(&mut self, _req: &Request, node_id: u64, reply: ReplyAttr) {
        let node_ptr = TreePtr::<Node>::new(node_id as u32);
        match self.fs.tx(|tx| tx.read_tree(node_ptr)) {
            Ok(node) => {
                reply.attr(&TTL, &node_attr(&node));
            }
            Err(err) => {
                reply.error(err.errno);
            }
        }
    }

    fn setattr(
        &mut self,
        _req: &Request,
        node_id: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let node_ptr = TreePtr::<Node>::new(node_id as u32);

        let mut node = match self.fs.tx(|tx| tx.read_tree(node_ptr)) {
            Ok(ok) => ok,
            Err(err) => {
                reply.error(err.errno);
                return;
            }
        };
        let mut node_changed = false;

        if let Some(mode) = mode {
            if node.data().mode() & Node::MODE_PERM != mode as u16 & Node::MODE_PERM {
                let new_mode =
                    (node.data().mode() & Node::MODE_TYPE) | (mode as u16 & Node::MODE_PERM);
                node.data_mut().set_mode(new_mode);
                node_changed = true;
            }
        }

        if let Some(uid) = uid {
            if node.data().uid() != uid {
                node.data_mut().set_uid(uid);
                node_changed = true;
            }
        }

        if let Some(gid) = gid {
            if node.data().gid() != gid {
                node.data_mut().set_gid(gid);
                node_changed = true;
            }
        }

        if let Some(atime) = atime {
            let atime_c = match atime {
                SpecificTime(st) => st.duration_since(UNIX_EPOCH).unwrap(),
                Now => SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
            };
            node.data_mut()
                .set_atime(atime_c.as_secs(), atime_c.subsec_nanos());
            node_changed = true;
        }

        if let Some(mtime) = mtime {
            let mtime_c = match mtime {
                SpecificTime(st) => st.duration_since(UNIX_EPOCH).unwrap(),
                Now => SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
            };
            node.data_mut()
                .set_mtime(mtime_c.as_secs(), mtime_c.subsec_nanos());
            node_changed = true;
        }

        if let Some(size) = size {
            match self.fs.tx(|tx| tx.truncate_node_inner(&mut node, size)) {
                Ok(ok) => {
                    if ok {
                        node_changed = true;
                    }
                }
                Err(err) => {
                    reply.error(err.errno);
                    return;
                }
            }
        }

        let attr = node_attr(&node);

        if node_changed {
            if let Err(err) = self.fs.tx(|tx| tx.sync_tree(node)) {
                reply.error(err.errno);
                return;
            }
        }

        reply.attr(&TTL, &attr);
    }

    fn read(
        &mut self,
        _req: &Request,
        node_id: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let node_ptr = TreePtr::<Node>::new(node_id as u32);

        let atime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let mut data = vec![0; size as usize];
        match self.fs.tx(|tx| {
            tx.read_node(
                node_ptr,
                cmp::max(0, offset) as u64,
                &mut data,
                atime.as_secs(),
                atime.subsec_nanos(),
            )
        }) {
            Ok(count) => {
                reply.data(&data[..count]);
            }
            Err(err) => {
                reply.error(err.errno);
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        node_id: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let node_ptr = TreePtr::<Node>::new(node_id as u32);

        let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.tx(|tx| {
            tx.write_node(
                node_ptr,
                cmp::max(0, offset) as u64,
                data,
                mtime.as_secs(),
                mtime.subsec_nanos(),
            )
        }) {
            Ok(count) => {
                reply.written(count as u32);
            }
            Err(err) => {
                reply.error(err.errno);
            }
        }
    }

    fn flush(&mut self, _req: &Request, _ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        reply.ok();
    }

    fn fsync(&mut self, _req: &Request, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request,
        parent_id: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let parent_ptr = TreePtr::new(parent_id as u32);
        let mut children = Vec::new();
        match self.fs.tx(|tx| tx.child_nodes(parent_ptr, &mut children)) {
            Ok(()) => {
                let mut i;
                let skip;
                if offset == 0 {
                    skip = 0;
                    i = 0;
                    let _full = reply.add(parent_id, i, FileType::Directory, ".");

                    i += 1;
                    let _full = reply.add(
                        //TODO: get parent?
                        parent_id,
                        i,
                        FileType::Directory,
                        "..",
                    );
                    i += 1;
                } else {
                    i = offset + 1;
                    skip = offset as usize - 1;
                }

                for child in children.iter().skip(skip) {
                    //TODO: make it possible to get file type from directory entry
                    let node = match self.fs.tx(|tx| tx.read_tree(child.node_ptr())) {
                        Ok(ok) => ok,
                        Err(err) => {
                            reply.error(err.errno);
                            return;
                        }
                    };

                    let full = reply.add(
                        child.node_ptr().id() as u64,
                        i,
                        if node.data().is_dir() {
                            FileType::Directory
                        } else {
                            FileType::RegularFile
                        },
                        child.name().unwrap(),
                    );

                    if full {
                        break;
                    }

                    i += 1;
                }
                reply.ok();
            }
            Err(err) => {
                reply.error(err.errno);
            }
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent_id: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_ptr = TreePtr::<Node>::new(parent_id as u32);
        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.tx(|tx| {
            tx.create_node(
                parent_ptr,
                name.to_str().unwrap(),
                Node::MODE_FILE | (mode as u16 & Node::MODE_PERM),
                ctime.as_secs(),
                ctime.subsec_nanos(),
            )
        }) {
            Ok(node) => {
                // println!("Create {:?}:{:o}:{:o}", node.1.name(), node.1.mode, mode);
                reply.created(&TTL, &node_attr(&node), 0, 0, 0);
            }
            Err(error) => {
                reply.error(error.errno);
            }
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent_id: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent_ptr = TreePtr::<Node>::new(parent_id as u32);
        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.tx(|tx| {
            tx.create_node(
                parent_ptr,
                name.to_str().unwrap(),
                Node::MODE_DIR | (mode as u16 & Node::MODE_PERM),
                ctime.as_secs(),
                ctime.subsec_nanos(),
            )
        }) {
            Ok(node) => {
                // println!("Mkdir {:?}:{:o}:{:o}", node.1.name(), node.1.mode, mode);
                reply.entry(&TTL, &node_attr(&node), 0);
            }
            Err(error) => {
                reply.error(error.errno);
            }
        }
    }

    fn rmdir(&mut self, _req: &Request, parent_id: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_ptr = TreePtr::<Node>::new(parent_id as u32);
        match self
            .fs
            .tx(|tx| tx.remove_node(parent_ptr, name.to_str().unwrap(), Node::MODE_DIR))
        {
            Ok(()) => {
                reply.ok();
            }
            Err(err) => {
                reply.error(err.errno);
            }
        }
    }

    fn unlink(&mut self, _req: &Request, parent_id: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_ptr = TreePtr::<Node>::new(parent_id as u32);
        match self
            .fs
            .tx(|tx| tx.remove_node(parent_ptr, name.to_str().unwrap(), Node::MODE_FILE))
        {
            Ok(()) => {
                reply.ok();
            }
            Err(err) => {
                reply.error(err.errno);
            }
        }
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        let bsize = BLOCK_SIZE;
        let blocks = self.fs.header.size() / bsize;
        let bfree = self.fs.allocator().free();
        reply.statfs(blocks, bfree, bfree, 0, 0, bsize as u32, 256, 0);
    }

    fn symlink(
        &mut self,
        _req: &Request,
        parent_id: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        let parent_ptr = TreePtr::<Node>::new(parent_id as u32);
        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.tx(|tx| {
            let node = tx.create_node(
                parent_ptr,
                name.to_str().unwrap(),
                Node::MODE_SYMLINK | 0o777,
                ctime.as_secs(),
                ctime.subsec_nanos(),
            )?;

            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            tx.write_node(
                node.ptr(),
                0,
                link.as_os_str().as_bytes(),
                mtime.as_secs(),
                mtime.subsec_nanos(),
            )?;

            Ok(node)
        }) {
            Ok(node) => {
                reply.entry(&TTL, &node_attr(&node), 0);
            }
            Err(error) => {
                reply.error(error.errno);
            }
        }
    }

    fn readlink(&mut self, _req: &Request, node_id: u64, reply: ReplyData) {
        let node_ptr = TreePtr::<Node>::new(node_id as u32);
        let atime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let mut data = vec![0; 4096];
        match self.fs.tx(|tx| {
            tx.read_node(
                node_ptr,
                0,
                &mut data,
                atime.as_secs(),
                atime.subsec_nanos(),
            )
        }) {
            Ok(count) => {
                reply.data(&data[..count]);
            }
            Err(err) => {
                reply.error(err.errno);
            }
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        orig_parent: u64,
        orig_name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let orig_parent_ptr = TreePtr::<Node>::new(orig_parent as u32);
        let orig_name = orig_name.to_str().expect("name is not utf-8");
        let new_parent_ptr = TreePtr::<Node>::new(new_parent as u32);
        let new_name = new_name.to_str().expect("name is not utf-8");

        // TODO: improve performance
        match self
            .fs
            .tx(|tx| tx.rename_node(orig_parent_ptr, orig_name, new_parent_ptr, new_name))
        {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(err.errno),
        }
    }
}
