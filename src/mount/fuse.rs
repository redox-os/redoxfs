extern crate fuse;
extern crate time;

use std::cmp;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{filesystem, Disk, Node, TreeData, TreePtr, BLOCK_SIZE};

use self::fuse::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyStatfs, ReplyWrite, Request, Session,
};
use self::time::Timespec;

const TTL: Timespec = Timespec { sec: 1, nsec: 0 }; // 1 second

const NULL_TIME: Timespec = Timespec { sec: 0, nsec: 0 };

pub fn mount<D, P, T, F>(
    filesystem: filesystem::FileSystem<D>,
    mountpoint: P,
    mut callback: F,
) -> io::Result<T>
where
    D: Disk,
    P: AsRef<Path>,
    F: FnMut(&Path) -> T,
{
    let mountpoint = mountpoint.as_ref();

    // One of the uses of this redoxfs fuse wrapper is to populate a filesystem
    // while building the Redox OS kernel. This means that we need to write on
    // a filesystem that belongs to `root`, which in turn means that we need to
    // be `root`, thus that we need to allow `root` to have access.
    let defer_permissions = [OsStr::new("-o"), OsStr::new("defer_permissions")];

    let mut session = Session::new(
        Fuse { fs: filesystem },
        mountpoint,
        if cfg!(target_os = "macos") {
            &defer_permissions
        } else {
            &[]
        },
    )?;

    let res = callback(mountpoint);

    session.run()?;

    Ok(res)
}

pub struct Fuse<D: Disk> {
    pub fs: filesystem::FileSystem<D>,
}

fn node_attr(node: &TreeData<Node>) -> FileAttr {
    FileAttr {
        ino: node.id() as u64,
        size: node.data().size(),
        // Blocks is in 512 byte blocks, not in our block size
        blocks: (node.data().size() + BLOCK_SIZE - 1) / BLOCK_SIZE * (BLOCK_SIZE / 512),
        atime: Timespec {
            sec: node.data().atime().0 as i64,
            nsec: node.data().atime().1 as i32,
        },
        mtime: Timespec {
            sec: node.data().mtime().0 as i64,
            nsec: node.data().mtime().1 as i32,
        },
        ctime: Timespec {
            sec: node.data().ctime().0 as i64,
            nsec: node.data().ctime().1 as i32,
        },
        crtime: NULL_TIME,
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

impl<D: Disk> Filesystem for Fuse<D> {
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
                reply.error(err.errno as i32);
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
                reply.error(err.errno as i32);
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
        atime: Option<Timespec>,
        mtime: Option<Timespec>,
        _fh: Option<u64>,
        _crtime: Option<Timespec>,
        _chgtime: Option<Timespec>,
        _bkuptime: Option<Timespec>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let node_ptr = TreePtr::<Node>::new(node_id as u32);

        let mut node = match self.fs.tx(|tx| tx.read_tree(node_ptr)) {
            Ok(ok) => ok,
            Err(err) => {
                reply.error(err.errno as i32);
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
            node.data_mut()
                .set_atime(atime.sec as u64, atime.nsec as u32);
            node_changed = true;
        }

        if let Some(mtime) = mtime {
            node.data_mut()
                .set_mtime(mtime.sec as u64, mtime.nsec as u32);
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
                    reply.error(err.errno as i32);
                    return;
                }
            }
        }

        let attr = node_attr(&node);

        if node_changed {
            if let Err(err) = self.fs.tx(|tx| tx.sync_tree(node)) {
                reply.error(err.errno as i32);
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
                reply.error(err.errno as i32);
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
        _flags: u32,
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
                reply.error(err.errno as i32);
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
                    reply.add(parent_id, i, FileType::Directory, ".");
                    i += 1;
                    reply.add(
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
                            reply.error(err.errno as i32);
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
                reply.error(err.errno as i32);
            }
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent_id: u64,
        name: &OsStr,
        mode: u32,
        flags: u32,
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
                reply.created(&TTL, &node_attr(&node), 0, 0, flags);
            }
            Err(error) => {
                reply.error(error.errno as i32);
            }
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent_id: u64,
        name: &OsStr,
        mode: u32,
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
                reply.error(error.errno as i32);
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
                reply.error(err.errno as i32);
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
                reply.error(err.errno as i32);
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
                reply.error(error.errno as i32);
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
                reply.error(err.errno as i32);
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
            Err(err) => reply.error(err.errno as i32),
        }
    }
}
