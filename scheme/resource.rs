use redoxfs::FileSystem;

use std::cmp::{min, max};

use syscall::error::{Error, Result, EINVAL};
use syscall::{Stat, SEEK_SET, SEEK_CUR, SEEK_END};

pub trait Resource {
    fn dup(&self) -> Result<Box<Resource>>;
    fn read(&mut self, buf: &mut [u8], fs: &mut FileSystem) -> Result<usize>;
    fn write(&mut self, buf: &[u8], fs: &mut FileSystem) -> Result<usize>;
    fn seek(&mut self, offset: usize, whence: usize, fs: &mut FileSystem) -> Result<usize>;
    fn path(&self, buf: &mut [u8]) -> Result<usize>;
    fn stat(&self, _stat: &mut Stat, fs: &mut FileSystem) -> Result<usize>;
    fn sync(&mut self) -> Result<usize>;
    fn truncate(&mut self, len: usize, fs: &mut FileSystem) -> Result<usize>;
}

pub struct DirResource {
    path: String,
    block: u64,
    data: Vec<u8>,
    seek: usize,
}

impl DirResource {
    pub fn new(path: String, block: u64, data: Vec<u8>) -> DirResource {
        DirResource {
            path: path,
            block: block,
            data: data,
            seek: 0,
        }
    }
}

impl Resource for DirResource {
    fn dup(&self) -> Result<Box<Resource>> {
        Ok(Box::new(DirResource {
            path: self.path.clone(),
            block: self.block,
            data: self.data.clone(),
            seek: self.seek
        }))
    }

    fn read(&mut self, buf: &mut [u8], _fs: &mut FileSystem) -> Result<usize> {
        let mut i = 0;
        while i < buf.len() && self.seek < self.data.len() {
            buf[i] = self.data[self.seek];
            i += 1;
            self.seek += 1;
        }
        Ok(i)
    }

    fn write(&mut self, _buf: &[u8], _fs: &mut FileSystem) -> Result<usize> {
        Err(Error::new(EINVAL))
    }

    fn seek(&mut self, offset: usize, whence: usize, _fs: &mut FileSystem) -> Result<usize> {
        self.seek = match whence {
            SEEK_SET => min(0, max(self.data.len() as isize, offset as isize)) as usize,
            SEEK_CUR => min(0, max(self.data.len() as isize, self.seek as isize + offset as isize)) as usize,
            SEEK_END => min(0, max(self.data.len() as isize, self.data.len() as isize + offset as isize)) as usize,
            _ => return Err(Error::new(EINVAL))
        };

        Ok(self.seek)
    }

    fn path(&self, buf: &mut [u8]) -> Result<usize> {
        let path = self.path.as_bytes();

        let mut i = 0;
        while i < buf.len() && i < path.len() {
            buf[i] = path[i];
            i += 1;
        }

        Ok(i)
    }

    fn stat(&self, stat: &mut Stat, fs: &mut FileSystem) -> Result<usize> {
        let node = try!(fs.node(self.block));

        stat.st_mode = node.1.mode;
        stat.st_uid = node.1.uid;
        stat.st_gid = node.1.gid;
        stat.st_size = try!(fs.node_len(self.block));

        Ok(0)
    }

    fn sync(&mut self) -> Result<usize> {
        Err(Error::new(EINVAL))
    }

    fn truncate(&mut self, _len: usize, _fs: &mut FileSystem) -> Result<usize> {
        Err(Error::new(EINVAL))
    }
}

pub struct FileResource {
    path: String,
    block: u64,
    seek: u64,
}

impl FileResource {
    pub fn new(path: String, block: u64) -> FileResource {
        FileResource {
            path: path,
            block: block,
            seek: 0,
        }
    }
}

impl Resource for FileResource {
    fn dup(&self) -> Result<Box<Resource>> {
        Ok(Box::new(FileResource {
            path: self.path.clone(),
            block: self.block,
            seek: self.seek,
        }))
    }

    fn read(&mut self, buf: &mut [u8], fs: &mut FileSystem) -> Result<usize> {
        let count = try!(fs.read_node(self.block, self.seek, buf));
        self.seek += count as u64;
        Ok(count)
    }

    fn write(&mut self, buf: &[u8], fs: &mut FileSystem) -> Result<usize> {
        let count = try!(fs.write_node(self.block, self.seek, buf));
        self.seek += count as u64;
        Ok(count)
    }

    fn seek(&mut self, offset: usize, whence: usize, fs: &mut FileSystem) -> Result<usize> {
        let size = try!(fs.node_len(self.block));

        self.seek = match whence {
            SEEK_SET => min(0, max(size as i64, offset as i64)) as u64,
            SEEK_CUR => min(0, max(size as i64, self.seek as i64 + offset as i64)) as u64,
            SEEK_END => min(0, max(size as i64, size as i64 + offset as i64)) as u64,
            _ => return Err(Error::new(EINVAL))
        };

        Ok(self.seek as usize)
    }

    fn path(&self, buf: &mut [u8]) -> Result<usize> {
        let path = self.path.as_bytes();

        let mut i = 0;
        while i < buf.len() && i < path.len() {
            buf[i] = path[i];
            i += 1;
        }

        Ok(i)
    }

    fn stat(&self, stat: &mut Stat, fs: &mut FileSystem) -> Result<usize> {
        let node = try!(fs.node(self.block));

        stat.st_mode = node.1.mode;
        stat.st_uid = node.1.uid;
        stat.st_gid = node.1.gid;
        stat.st_size = try!(fs.node_len(self.block));

        Ok(0)
    }

    fn sync(&mut self) -> Result<usize> {
        Ok(0)
    }

    fn truncate(&mut self, len: usize, fs: &mut FileSystem) -> Result<usize> {
        try!(fs.node_set_len(self.block, len as u64));

        Ok(0)
    }
}
