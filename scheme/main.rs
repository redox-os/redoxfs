extern crate redoxfs;

extern crate system;

use std::cmp::{min, max};
use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;

use image::Image;

use redoxfs::{FileSystem, Node};

use system::error::{Error, Result, EISDIR, EPERM, ENOENT, EBADF, EINVAL};
use system::scheme::{Packet, Scheme};
use system::syscall::{Stat, O_CREAT, SEEK_SET, SEEK_CUR, SEEK_END};

pub mod image;

struct FileResource {
    path: String,
    data: Vec<u8>,
    seek: usize,
}

impl FileResource {
    fn new(path: &str, data: Vec<u8>) -> FileResource {
        FileResource {
            path: path.to_string(),
            data: data,
            seek: 0,
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        while i < buf.len() && self.seek < self.data.len() {
            buf[i] = self.data[self.seek];
            i += 1;
            self.seek += 1;
        }
        Ok(i)
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut i = 0;
        while i < buf.len() && self.seek < self.data.len() {
            self.data[self.seek] = buf[i];
            i += 1;
            self.seek += 1;
        }
        Ok(i)
    }

    fn seek(&mut self, offset: usize, whence: usize) -> Result<usize> {
        match whence {
            SEEK_SET => {
                self.seek = min(0, max(self.data.len() as isize, offset as isize)) as usize;
                Ok(self.seek)
            },
            SEEK_CUR => {
                self.seek = min(0, max(self.data.len() as isize, self.seek as isize + offset as isize)) as usize;
                Ok(self.seek)
            },
            SEEK_END => {
                self.seek = min(0, max(self.data.len() as isize, self.data.len() as isize + offset as isize)) as usize;
                Ok(self.seek)
            },
            _ => Err(Error::new(EINVAL))
        }
    }

    fn path(&self, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        let path = self.path.as_bytes();
        while i < buf.len() && i < path.len() {
            buf[i] = path[i];
            i += 1;
        }
        Ok(i)
    }

    fn stat(&self, _stat: &mut Stat) -> Result<usize> {
        Ok(0)
    }

    fn sync(&mut self) -> Result<usize> {
        Ok(0)
    }
}

struct FileScheme {
    fs: FileSystem,
    next_id: isize,
    files: BTreeMap<usize, FileResource>
}

impl FileScheme {
    fn new(fs: FileSystem) -> FileScheme {
        FileScheme {
            fs: fs,
            next_id: 1,
            files: BTreeMap::new()
        }
    }

    fn path_nodes(&mut self, path: &str, nodes: &mut Vec<(u64, Node)>) -> Result<(u64, Node)> {
        let mut block = self.fs.header.1.root;
        nodes.push(try!(self.fs.node(block)));

        for part in path.split('/') {
            if ! part.is_empty() {
                let node = try!(self.fs.find_node(part, block));
                block = node.0;
                nodes.push(node);
            }
        }

        Ok(nodes.pop().unwrap())
    }
}

impl Scheme for FileScheme {
    fn open(&mut self, url: &str, flags: usize, _mode: usize) -> Result<usize> {
        let path = url.split(':').nth(1).unwrap_or("").trim_matches('/');

        let mut nodes = Vec::new();
        let node_result = self.path_nodes(path, &mut nodes);

        let mut data = Vec::new();
        match node_result {
            Ok(node) => if node.1.is_dir() {
                let mut children = Vec::new();
                try!(self.fs.child_nodes(&mut children, node.0));
                for child in children.iter() {
                    if let Ok(name) = child.1.name() {
                        if ! data.is_empty() {
                            data.push('\n' as u8);
                        }
                        data.extend_from_slice(&name.as_bytes());
                    }
                }
            } else {
                for i in 0..try!(self.fs.node_len(node.0)) {
                    let mut sector = [0; 512];
                    try!(self.fs.read_node(node.0, i as usize * 512, &mut sector));
                    data.extend_from_slice(&sector);
                }
            },
            Err(err) => if err.errno == ENOENT && flags & O_CREAT == O_CREAT {
                let mut last_part = String::new();
                for part in path.split('/') {
                    if ! part.is_empty() {
                        last_part = part.to_string();
                    }
                }
                if ! last_part.is_empty() {
                    if let Some(parent) = nodes.last() {
                        try!(self.fs.create_node(Node::MODE_FILE, &last_part, parent.0));
                    } else {
                        return Err(Error::new(EPERM));
                    }
                } else {
                    return Err(Error::new(EPERM));
                }
            } else {
                return Err(err);
            }
        }
        /*
        if let Some(arg) = args.next() {
            match  {
                Ok(node) => println!("{}: {:#?}", node.0, node.1),
                Err(err) => println!("mk: failed to create {}: {}", arg, err)
            }
        } else {
            println!("mk <file>");
        }
        */

        let id = self.next_id as usize;
        self.next_id += 1;
        if self.next_id < 0 {
            self.next_id = 1;
        }
        self.files.insert(id, FileResource::new(url, data));
        Ok(id)
    }

    fn mkdir(&mut self, path: &str, mode: usize) -> Result<usize> {
        println!("mkdir {}, {:X}", path, mode);
        Err(Error::new(ENOENT))
    }

    /*
    fn rmdir(&mut self, path: &str) -> Result<usize> {
        println!("rmdir {}", path);
        Err(Error::new(ENOENT))
    }
    */

    fn unlink(&mut self, url: &str) -> Result<usize> {
        let path = url.split(':').nth(1).unwrap_or("").trim_matches('/');
        let mut nodes = Vec::new();
        let child = try!(self.path_nodes(path, &mut nodes));
        if let Some(parent) = nodes.last() {
            if ! child.1.is_dir() {
                if let Ok(child_name) = child.1.name() {
                    self.fs.remove_node(Node::MODE_FILE, child_name, parent.0).and(Ok(0))
                } else {
                    Err(Error::new(ENOENT))
                }
            } else {
                Err(Error::new(EISDIR))
            }
        } else {
            Err(Error::new(EPERM))
        }
    }

    /* Resource operations */
    #[allow(unused_variables)]
    fn read(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        if let Some(mut file) = self.files.get_mut(&id) {
            file.read(buf)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn write(&mut self, id: usize, buf: &[u8]) -> Result<usize> {
        if let Some(mut file) = self.files.get_mut(&id) {
            file.write(buf)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn seek(&mut self, id: usize, pos: usize, whence: usize) -> Result<usize> {
        if let Some(mut file) = self.files.get_mut(&id) {
            file.seek(pos, whence)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        if let Some(file) = self.files.get(&id) {
            file.path(buf)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        println!("fstat {}, {:X}", id, stat as *mut Stat as usize);
        if let Some(file) = self.files.get(&id) {
            file.stat(stat)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn fsync(&mut self, id: usize) -> Result<usize> {
        println!("fsync {}", id);
        if let Some(mut file) = self.files.get_mut(&id) {
            file.sync()
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn ftruncate(&mut self, id: usize, len: usize) -> Result<usize> {
        println!("ftruncate {}, {}", id, len);
        Err(Error::new(EBADF))
    }

    fn close(&mut self, id: usize) -> Result<usize> {
        if self.files.remove(&id).is_some() {
            Ok(0)
        } else {
            Err(Error::new(EBADF))
        }
    }
}

fn scheme(fs: FileSystem) {
   //In order to handle example:, we create :example
   let mut scheme = FileScheme::new(fs);
   let mut socket = File::create(":redoxfs").unwrap();
   loop {
       let mut packet = Packet::default();
       while socket.read(&mut packet).unwrap() == size_of::<Packet>() {
           scheme.handle(&mut packet);
           socket.write(&packet).unwrap();
       }
   }
}

fn main() {
    let mut args = env::args();
    if let Some(path) = args.nth(1) {
        //Open an existing image
        match Image::open(&path) {
            Ok(disk) => match FileSystem::open(Box::new(disk)) {
                Ok(filesystem) => {
                    println!("redoxfs: opened filesystem {}", path);
                    scheme(filesystem);
                },
                Err(err) => println!("redoxfs: failed to open filesystem {}: {}", path, err)
            },
            Err(err) => println!("redoxfs: failed to open image {}: {}", path, err)
        }
    } else {
        println!("redoxfs: no disk image provided");
    }
}
