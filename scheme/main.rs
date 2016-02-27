extern crate redoxfs;

extern crate system;

use std::cmp::{min, max};
use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;

use image::Image;

use redoxfs::FileSystem;

use system::error::{Error, Result, ENOENT, EBADF, EINVAL};
use system::scheme::{Packet, Scheme};
use system::syscall::{Stat, SEEK_SET, SEEK_CUR, SEEK_END};

pub mod image;

struct FileResource {
    path: String,
    data: Vec<u8>,
    seek: usize,
}

impl FileResource {
    fn new(path: &str) -> FileResource {
        FileResource {
            path: path.to_string(),
            data: Vec::new(),
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
}

impl Scheme for FileScheme {
    fn open(&mut self, path: &str, flags: usize, mode: usize) -> Result<usize> {
        println!("open {:X} = {}, {:X}, {:X}", path.as_ptr() as usize, path, flags, mode);
        let id = self.next_id as usize;
        self.next_id += 1;
        if self.next_id < 0 {
            self.next_id = 1;
        }
        self.files.insert(id, FileResource::new(path));
        Ok(id)
    }

    #[allow(unused_variables)]
    fn unlink(&mut self, path: &str) -> Result<usize> {
        println!("unlink {}", path);
        Err(Error::new(ENOENT))
    }

    #[allow(unused_variables)]
    fn mkdir(&mut self, path: &str, mode: usize) -> Result<usize> {
        println!("mkdir {}, {:X}", path, mode);
        Err(Error::new(ENOENT))
    }

    /* Resource operations */
    #[allow(unused_variables)]
    fn read(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        println!("read {}, {:X}, {}", id, buf.as_mut_ptr() as usize, buf.len());
        if let Some(mut file) = self.files.get_mut(&id) {
            file.read(buf)
        } else {
            Err(Error::new(EBADF))
        }
    }

    #[allow(unused_variables)]
    fn write(&mut self, id: usize, buf: &[u8]) -> Result<usize> {
        println!("write {}, {:X}, {}", id, buf.as_ptr() as usize, buf.len());
        if let Some(mut file) = self.files.get_mut(&id) {
            file.write(buf)
        } else {
            Err(Error::new(EBADF))
        }
    }

    #[allow(unused_variables)]
    fn seek(&mut self, id: usize, pos: usize, whence: usize) -> Result<usize> {
        println!("seek {}, {}, {}", id, pos, whence);
        if let Some(mut file) = self.files.get_mut(&id) {
            file.seek(pos, whence)
        } else {
            Err(Error::new(EBADF))
        }
    }

    #[allow(unused_variables)]
    fn fpath(&self, id: usize, buf: &mut [u8]) -> Result<usize> {
        println!("fpath {}, {:X}, {}", id, buf.as_mut_ptr() as usize, buf.len());
        if let Some(file) = self.files.get(&id) {
            file.path(buf)
        } else {
            Err(Error::new(EBADF))
        }
    }

    #[allow(unused_variables)]
    fn fstat(&self, id: usize, stat: &mut Stat) -> Result<usize> {
        println!("fstat {}, {:X}", id, stat as *mut Stat as usize);
        if let Some(file) = self.files.get(&id) {
            file.stat(stat)
        } else {
            Err(Error::new(EBADF))
        }
    }

    #[allow(unused_variables)]
    fn fsync(&mut self, id: usize) -> Result<usize> {
        println!("fsync {}", id);
        if let Some(mut file) = self.files.get_mut(&id) {
            file.sync()
        } else {
            Err(Error::new(EBADF))
        }
    }

    #[allow(unused_variables)]
    fn ftruncate(&mut self, id: usize, len: usize) -> Result<usize> {
        println!("ftruncate {}, {}", id, len);
        Err(Error::new(EBADF))
    }

    fn close(&mut self, id: usize) -> Result<usize> {
        println!("close {}", id);
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
