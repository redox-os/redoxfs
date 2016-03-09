//#![deny(warnings)]

extern crate fuse;
extern crate redoxfs;
extern crate system;
extern crate time;

use image::Image;
use std::env;
use std::path::Path;
use time::Timespec;
use fuse::{FileType, FileAttr, Filesystem, Request, ReplyData, ReplyEntry, ReplyAttr, ReplyDirectory};
use system::error::ENOENT;

pub mod image;

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };                 // 1 second

const CREATE_TIME: Timespec = Timespec { sec: 0, nsec: 0 };

const HELLO_TXT_CONTENT: &'static str = "Hello World!\n";

struct RedoxFS {
    fs: redoxfs::FileSystem,
}

impl Filesystem for RedoxFS {
    fn lookup (&mut self, _req: &Request, ino: u64, name: &Path, reply: ReplyEntry) {
        let parent_block = self.fs.header.0 + ino;
        println!("lookup: {} {:?}", parent_block, name);
        match self.fs.find_node(name.to_str().unwrap(), parent_block) {
            Ok(node) => {
                println!("lookup: {:?}", node);
                reply.entry(&TTL, &FileAttr {
                    ino: node.0 - self.fs.header.0,
                    size: node.1.extents[0].length,
                    blocks: (node.1.extents[0].length + 511)/512,
                    atime: CREATE_TIME,
                    mtime: CREATE_TIME,
                    ctime: CREATE_TIME,
                    crtime: CREATE_TIME,
                    kind: if node.1.is_dir() {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    },
                    perm: 0o777,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    flags: 0,
                }, 0)
            },
            Err(err) => {
                println!("lookup: {}", err);
                reply.error(err.errno as i32);
            }
        }
    }

    fn getattr (&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let block = self.fs.header.0 + ino;
        println!("getattr: {}", block);
        match self.fs.node(block) {
            Ok(node) => {
                println!("getattr: {:?}", node);
                reply.attr(&TTL, &FileAttr {
                    ino: node.0 - self.fs.header.0,
                    size: node.1.extents[0].length,
                    blocks: (node.1.extents[0].length + 511)/512,
                    atime: CREATE_TIME,
                    mtime: CREATE_TIME,
                    ctime: CREATE_TIME,
                    crtime: CREATE_TIME,
                    kind: if node.1.is_dir() {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    },
                    perm: 0o777,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    flags: 0,
                });
            },
            Err(err) => {
                println!("getattr: {}", err);
                reply.error(err.errno as i32);
            }
        }
    }

    fn read (&mut self, _req: &Request, ino: u64, _fh: u64, offset: u64, _size: u32, reply: ReplyData) {
        if ino == 2 {
            reply.data(&HELLO_TXT_CONTENT.as_bytes()[offset as usize..]);
        } else {
            reply.error(ENOENT as i32);
        }
    }

    fn readdir (&mut self, _req: &Request, ino: u64, _fh: u64, offset: u64, mut reply: ReplyDirectory) {
        let parent_block = self.fs.header.0 + ino;
        println!("readdir: {}", parent_block);
        let mut children = Vec::new();
        match self.fs.child_nodes(&mut children, parent_block) {
            Ok(()) => {
                if offset == 0 {
                    let mut i = 0;
                    reply.add(parent_block - self.fs.header.0, i, FileType::Directory, ".");
                    i += 1;
                    reply.add(parent_block - self.fs.header.0, i, FileType::Directory, "..");
                    i += 1;
                    for child in children.iter() {
                        reply.add(child.0 - self.fs.header.0, i, if child.1.is_dir() {
                            FileType::Directory
                        } else {
                            FileType::RegularFile
                        }, child.1.name().unwrap());
                        i += 1;
                    }
                }
                reply.ok();
            },
            Err(err) => {
                println!("readdir: {}", err);
                reply.error(err.errno as i32);
            }
        }
    }
}

fn main () {
    if let Some(path) = env::args().nth(1) {
        //Open an existing image
        match Image::open(&path) {
            Ok(disk) => match redoxfs::FileSystem::open(Box::new(disk)) {
                Ok(filesystem) => {
                    println!("redoxfs: opened filesystem {}", path);

                    if let Some(mountpoint) = env::args_os().nth(2) {
                        fuse::mount(RedoxFS {
                            fs: filesystem
                        }, &mountpoint, &[]);
                    } else {
                        println!("redoxfs: no mount point provided");
                    }
                },
                Err(err) => println!("redoxfs: failed to open filesystem {}: {}", path, err)
            },
            Err(err) => println!("redoxfs: failed to open image {}: {}", path, err)
        }
    } else {
        println!("redoxfs: no disk image provided");
    }
}
