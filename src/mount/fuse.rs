extern crate fuse;
extern crate time;

use std::cmp;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use disk::Disk;
use filesystem;
use node::Node;
use BLOCK_SIZE;

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

    let res = callback(&mountpoint);

    session.run()?;

    Ok(res)
}

pub struct Fuse<D: Disk> {
    pub fs: filesystem::FileSystem<D>,
}

fn node_attr(node: &(u64, Node)) -> FileAttr {
    FileAttr {
        ino: node.0,
        size: node.1.extents[0].length,
        // Blocks is in 512 byte blocks, not in our block size
        blocks: (node.1.extents[0].length + BLOCK_SIZE - 1) / BLOCK_SIZE * (BLOCK_SIZE / 512),
        atime: NULL_TIME,
        mtime: Timespec {
            sec: node.1.mtime as i64,
            nsec: node.1.mtime_nsec as i32,
        },
        ctime: Timespec {
            sec: node.1.ctime as i64,
            nsec: node.1.ctime_nsec as i32,
        },
        crtime: NULL_TIME,
        kind: if node.1.is_dir() {
            FileType::Directory
        } else if node.1.is_symlink() {
            FileType::Symlink
        } else {
            FileType::RegularFile
        },
        perm: node.1.mode & Node::MODE_PERM,
        nlink: 1,
        uid: node.1.uid,
        gid: node.1.gid,
        rdev: 0,
        flags: 0,
    }
}

impl<D: Disk> Filesystem for Fuse<D> {
    fn lookup(&mut self, _req: &Request, parent_block: u64, name: &OsStr, reply: ReplyEntry) {
        match self.fs.find_node(name.to_str().unwrap(), parent_block) {
            Ok(node) => {
                reply.entry(&TTL, &node_attr(&node), 0);
            }
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn getattr(&mut self, _req: &Request, block: u64, reply: ReplyAttr) {
        match self.fs.node(block) {
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
        block: u64,
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
        if let Some(mode) = mode {
            match self.fs.node(block) {
                Ok(mut node) => {
                    if node.1.mode & Node::MODE_PERM != mode as u16 & Node::MODE_PERM {
                        // println!("Chmod {:?}:{:o}:{:o}", node.1.name(), node.1.mode, mode);
                        node.1.mode =
                            (node.1.mode & Node::MODE_TYPE) | (mode as u16 & Node::MODE_PERM);
                        if let Err(err) = self.fs.write_at(node.0, &node.1) {
                            reply.error(err.errno as i32);
                            return;
                        }
                    }
                }
                Err(err) => {
                    reply.error(err.errno as i32);
                    return;
                }
            }
        }

        if let Some(uid) = uid {
            match self.fs.node(block) {
                Ok(mut node) => {
                    if node.1.uid != uid {
                        node.1.uid = uid;
                        if let Err(err) = self.fs.write_at(node.0, &node.1) {
                            reply.error(err.errno as i32);
                            return;
                        }
                    }
                }
                Err(err) => {
                    reply.error(err.errno as i32);
                    return;
                }
            }
        }

        if let Some(gid) = gid {
            match self.fs.node(block) {
                Ok(mut node) => {
                    if node.1.gid != gid {
                        node.1.gid = gid;
                        if let Err(err) = self.fs.write_at(node.0, &node.1) {
                            reply.error(err.errno as i32);
                            return;
                        }
                    }
                }
                Err(err) => {
                    reply.error(err.errno as i32);
                    return;
                }
            }
        }

        if let Some(size) = size {
            if let Err(err) = self.fs.node_set_len(block, size) {
                reply.error(err.errno as i32);
                return;
            }
        }

        let need_update = atime.is_some() || mtime.is_some();
        if need_update {
            match self.fs.node(block) {
                Ok(mut node) => {
                    if let Some(atime) = atime {
                        node.1.atime = atime.sec as u64;
                        node.1.atime_nsec = atime.nsec as u32;
                    }

                    if let Some(mtime) = mtime {
                        node.1.mtime = mtime.sec as u64;
                        node.1.mtime_nsec = mtime.nsec as u32;
                    }

                    if let Err(err) = self.fs.write_at(node.0, &node.1) {
                        reply.error(err.errno as i32);
                        return;
                    }
                }
                Err(err) => {
                    reply.error(err.errno as i32);
                    return;
                }
            }
        }

        match self.fs.node(block) {
            Ok(node) => {
                reply.attr(&TTL, &node_attr(&node));
            }
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        block: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        reply: ReplyData,
    ) {
        let mut data = vec![0; size as usize];
        match self
            .fs
            .read_node(block, cmp::max(0, offset) as u64, &mut data)
        {
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
        block: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _flags: u32,
        reply: ReplyWrite,
    ) {
        let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.write_node(
            block,
            cmp::max(0, offset) as u64,
            &data,
            mtime.as_secs(),
            mtime.subsec_nanos(),
        ) {
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
        parent_block: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let mut children = Vec::new();
        match self.fs.child_nodes(&mut children, parent_block) {
            Ok(()) => {
                let mut i;
                let skip;
                if offset == 0 {
                    skip = 0;
                    i = 0;
                    reply.add(parent_block - self.fs.header.0, i, FileType::Directory, ".");
                    i += 1;
                    reply.add(
                        parent_block - self.fs.header.0,
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
                    let full = reply.add(
                        child.0 - self.fs.header.0,
                        i,
                        if child.1.is_dir() {
                            FileType::Directory
                        } else {
                            FileType::RegularFile
                        },
                        child.1.name().unwrap(),
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
        parent_block: u64,
        name: &OsStr,
        mode: u32,
        flags: u32,
        reply: ReplyCreate,
    ) {
        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.create_node(
            Node::MODE_FILE | (mode as u16 & Node::MODE_PERM),
            name.to_str().unwrap(),
            parent_block,
            ctime.as_secs(),
            ctime.subsec_nanos(),
        ) {
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
        parent_block: u64,
        name: &OsStr,
        mode: u32,
        reply: ReplyEntry,
    ) {
        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.create_node(
            Node::MODE_DIR | (mode as u16 & Node::MODE_PERM),
            name.to_str().unwrap(),
            parent_block,
            ctime.as_secs(),
            ctime.subsec_nanos(),
        ) {
            Ok(node) => {
                // println!("Mkdir {:?}:{:o}:{:o}", node.1.name(), node.1.mode, mode);
                reply.entry(&TTL, &node_attr(&node), 0);
            }
            Err(error) => {
                reply.error(error.errno as i32);
            }
        }
    }

    fn rmdir(&mut self, _req: &Request, parent_block: u64, name: &OsStr, reply: ReplyEmpty) {
        match self
            .fs
            .remove_node(Node::MODE_DIR, name.to_str().unwrap(), parent_block)
        {
            Ok(()) => {
                reply.ok();
            }
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn unlink(&mut self, _req: &Request, parent_block: u64, name: &OsStr, reply: ReplyEmpty) {
        match self
            .fs
            .remove_node(Node::MODE_FILE, name.to_str().unwrap(), parent_block)
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
        let free = self.fs.header.1.free;
        match self.fs.node_len(free) {
            Ok(free_size) => {
                let bsize = BLOCK_SIZE;
                let blocks = self.fs.header.1.size / bsize;
                let bfree = free_size / bsize;
                reply.statfs(blocks, bfree, bfree, 0, 0, bsize as u32, 256, 0);
            }
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn symlink(
        &mut self,
        _req: &Request,
        parent_block: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.create_node(
            Node::MODE_SYMLINK | 0o777,
            name.to_str().unwrap(),
            parent_block,
            ctime.as_secs(),
            ctime.subsec_nanos(),
        ) {
            Ok(node) => {
                let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                match self.fs.write_node(
                    node.0,
                    0,
                    link.as_os_str().as_bytes(),
                    mtime.as_secs(),
                    mtime.subsec_nanos(),
                ) {
                    Ok(_count) => {
                        reply.entry(&TTL, &node_attr(&node), 0);
                    }
                    Err(err) => {
                        reply.error(err.errno as i32);
                    }
                }
            }
            Err(error) => {
                reply.error(error.errno as i32);
            }
        }
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let mut data = vec![0; 4096];
        match self.fs.read_node(ino, 0, &mut data) {
            Ok(count) => {
                reply.data(&data[..count]);
            }
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn rename(&mut self, _req: &Request, orig_parent: u64, name: &OsStr, new_parent: u64, new_name: &OsStr, reply: ReplyEmpty) {
        let rename_inner = |fs: &mut filesystem::FileSystem<D>| -> syscall::Result<()> {
            let mut orig = fs.find_node(name.to_str().unwrap(), orig_parent)?;

            if new_parent != orig_parent {
                fs.remove_blocks(orig.0, 1, orig_parent)?;
            }

            if let Ok(node) = fs.find_node(new_name.to_str().unwrap(), new_parent) {
                if node.0 != orig.0 {
                    fs.node_set_len(node.0, 0)?;
                    fs.remove_blocks(node.0, 1, new_parent)?;
                    fs.write_at(node.0, &Node::default())?;
                    fs.deallocate(node.0, BLOCK_SIZE)?;
                }
            }

            orig.1.set_name(&new_name.to_str().unwrap())?;
            orig.1.parent = new_parent;
            fs.write_at(orig.0, &orig.1)?;

            if new_parent != orig_parent {
                fs.insert_blocks(orig.0, BLOCK_SIZE, new_parent)?;
            }

            Ok(())
        };

        match rename_inner(&mut self.fs) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(err.errno as i32),
        }
    }
}
