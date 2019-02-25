extern crate fuse;
extern crate time;

use std::cmp;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use BLOCK_SIZE;
use disk::Disk;
use filesystem;
use node::Node;

use self::fuse::{FileType, FileAttr, Filesystem, Request, ReplyData, ReplyEntry, ReplyAttr, ReplyCreate, ReplyDirectory, ReplyEmpty, ReplyStatfs, ReplyWrite, Session};
use self::time::Timespec;

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };                 // 1 second

const NULL_TIME: Timespec = Timespec { sec: 0, nsec: 0 };

pub fn mount<D: Disk, P: AsRef<Path>, F: FnMut()>(filesystem: filesystem::FileSystem<D>, mountpoint: &P, mut callback: F, options: &[&OsStr]) -> io::Result<()> {
    let mut session = Session::new(Fuse {
        fs: filesystem
    }, mountpoint.as_ref(), options)?;

    callback();

    session.run()
}

pub struct Fuse<D: Disk> {
    pub fs: filesystem::FileSystem<D>,
}

fn node_attr(node: &(u64, Node)) -> FileAttr {
    FileAttr {
        ino: node.0,
        size: node.1.extents[0].length,
        // Blocks is in 512 byte blocks, not in our block size
        blocks: (node.1.extents[0].length + BLOCK_SIZE - 1)/BLOCK_SIZE * (BLOCK_SIZE / 512),
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
            },
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn getattr(&mut self, _req: &Request, block: u64, reply: ReplyAttr) {
        match self.fs.node(block) {
            Ok(node) => {
                reply.attr(&TTL, &node_attr(&node));
            },
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn setattr(&mut self, _req: &Request, block: u64, mode: Option<u32>,
                uid: Option<u32>, gid: Option<u32>, size: Option<u64>,
                _atime: Option<Timespec>, mtime: Option<Timespec>, _fh: Option<u64>,
                _crtime: Option<Timespec>, _chgtime: Option<Timespec>, _bkuptime: Option<Timespec>,
                _flags: Option<u32>, reply: ReplyAttr) {
        if let Some(mode) = mode {
            match self.fs.node(block) {
                Ok(mut node) => if node.1.mode & Node::MODE_PERM != mode as u16 & Node::MODE_PERM {
                    // println!("Chmod {:?}:{:o}:{:o}", node.1.name(), node.1.mode, mode);
                    node.1.mode = (node.1.mode & Node::MODE_TYPE) | (mode as u16 & Node::MODE_PERM);
                    if let Err(err) = self.fs.write_at(node.0, &node.1) {
                        reply.error(err.errno as i32);
                        return;
                    }
                },
                Err(err) => {
                    reply.error(err.errno as i32);
                    return;
                }
            }
        }

        if let Some(uid) = uid {
            match self.fs.node(block) {
                Ok(mut node) => if node.1.uid != uid {
                    node.1.uid = uid;
                    if let Err(err) = self.fs.write_at(node.0, &node.1) {
                        reply.error(err.errno as i32);
                        return;
                    }
                },
                Err(err) => {
                    reply.error(err.errno as i32);
                    return;
                }
            }
        }

        if let Some(gid) = gid {
            match self.fs.node(block) {
                Ok(mut node) => if node.1.gid != gid {
                    node.1.gid = gid;
                    if let Err(err) = self.fs.write_at(node.0, &node.1) {
                        reply.error(err.errno as i32);
                        return;
                    }
                },
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

        if let Some(mtime) = mtime {
            match self.fs.node(block) {
                Ok(mut node) => {
                    node.1.mtime = mtime.sec as u64;
                    node.1.mtime_nsec = mtime.nsec as u32;
                    if let Err(err) = self.fs.write_at(node.0, &node.1) {
                        reply.error(err.errno as i32);
                        return;
                    }
                },
                Err(err) => {
                    reply.error(err.errno as i32);
                    return;
                }
            }
        }

        match self.fs.node(block) {
            Ok(node) => {
                reply.attr(&TTL, &node_attr(&node));
            },
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn read(&mut self, _req: &Request, block: u64, _fh: u64, offset: i64, size: u32, reply: ReplyData) {
        let mut data = vec![0; size as usize];
        match self.fs.read_node(block, cmp::max(0, offset) as u64, &mut data) {
            Ok(count) => {
                reply.data(&data[..count]);
            },
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn write(&mut self, _req: &Request, block: u64, _fh: u64, offset: i64, data: &[u8], _flags: u32, reply: ReplyWrite) {
        let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.write_node(block, cmp::max(0, offset) as u64, &data, mtime.as_secs(), mtime.subsec_nanos()) {
            Ok(count) => {
                reply.written(count as u32);
            },
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

    fn readdir(&mut self, _req: &Request, parent_block: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
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
                    reply.add(parent_block - self.fs.header.0, i, FileType::Directory, "..");
                    i += 1;
                } else {
                    i = offset + 1;
                    skip = offset as usize - 1;
                }

                for child in children.iter().skip(skip) {
                    let full = reply.add(child.0 - self.fs.header.0, i, if child.1.is_dir() {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    }, child.1.name().unwrap());

                    if full {
                        break;
                    }

                    i += 1;
                }
                reply.ok();
            },
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn create(&mut self, _req: &Request, parent_block: u64, name: &OsStr, mode: u32, flags: u32, reply: ReplyCreate) {
        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.create_node(Node::MODE_FILE | (mode as u16 & Node::MODE_PERM), name.to_str().unwrap(), parent_block, ctime.as_secs(), ctime.subsec_nanos()) {
            Ok(node) => {
                // println!("Create {:?}:{:o}:{:o}", node.1.name(), node.1.mode, mode);
                reply.created(&TTL, &node_attr(&node), 0, 0, flags);
            },
            Err(error) => {
                reply.error(error.errno as i32);
            }
        }
    }

    fn mkdir(&mut self, _req: &Request, parent_block: u64, name: &OsStr, mode: u32, reply: ReplyEntry) {
        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.create_node(Node::MODE_DIR | (mode as u16 & Node::MODE_PERM), name.to_str().unwrap(), parent_block, ctime.as_secs(), ctime.subsec_nanos()) {
            Ok(node) => {
                // println!("Mkdir {:?}:{:o}:{:o}", node.1.name(), node.1.mode, mode);
                reply.entry(&TTL, &node_attr(&node), 0);
            },
            Err(error) => {
                reply.error(error.errno as i32);
            }
        }
    }

    fn rmdir(&mut self, _req: &Request, parent_block: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.fs.remove_node(Node::MODE_DIR, name.to_str().unwrap(), parent_block) {
            Ok(()) => {
                reply.ok();
            },
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn unlink(&mut self, _req: &Request, parent_block: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.fs.remove_node(Node::MODE_FILE, name.to_str().unwrap(), parent_block) {
            Ok(()) => {
                reply.ok();
            },
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
                let blocks = self.fs.header.1.size/bsize;
                let bfree = free_size/bsize;
                reply.statfs(blocks, bfree, bfree, 0, 0, bsize as u32, 256, 0);
            },
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }

    fn symlink(&mut self, _req: &Request, parent_block: u64, name: &OsStr, link: &Path, reply: ReplyEntry) {
        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        match self.fs.create_node(Node::MODE_SYMLINK | 0o777, name.to_str().unwrap(), parent_block, ctime.as_secs(), ctime.subsec_nanos()) {
            Ok(node) => {
                let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                match self.fs.write_node(node.0, 0, link.as_os_str().as_bytes(), mtime.as_secs(), mtime.subsec_nanos()) {
                    Ok(_count) => {
                        reply.entry(&TTL, &node_attr(&node), 0);
                    },
                    Err(err) => {
                        reply.error(err.errno as i32);
                    }
                }
            },
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
            },
            Err(err) => {
                reply.error(err.errno as i32);
            }
        }
    }
}
