use redoxfs::FileSystem;

use std::cmp::{min, max};

use system::error::{Error, Result, EINVAL};
use system::syscall::{Stat, SEEK_SET, SEEK_CUR, SEEK_END, MODE_DIR, MODE_FILE};

pub trait Resource {
    fn read(&mut self, buf: &mut [u8], fs: &mut FileSystem) -> Result<usize>;

    fn write(&mut self, buf: &[u8], fs: &mut FileSystem) -> Result<usize>;

    fn seek(&mut self, offset: usize, whence: usize) -> Result<usize>;

    fn path(&self, buf: &mut [u8]) -> Result<usize>;

    fn stat(&self, _stat: &mut Stat) -> Result<usize>;

    fn sync(&mut self) -> Result<usize>;

    fn truncate(&mut self, len: usize, fs: &mut FileSystem) -> Result<usize>;
}

pub struct DirResource {
    path: String,
    data: Vec<u8>,
    seek: usize,
}

impl DirResource {
    pub fn new(path: &str, data: Vec<u8>) -> DirResource {
        DirResource {
            path: path.to_string(),
            data: data,
            seek: 0,
        }
    }
}

impl Resource for DirResource {
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

    fn seek(&mut self, offset: usize, whence: usize) -> Result<usize> {
        match whence {
            SEEK_SET => self.seek = min(0, max(self.data.len() as isize, offset as isize)) as usize,
            SEEK_CUR => self.seek = min(0, max(self.data.len() as isize, self.seek as isize + offset as isize)) as usize,
            SEEK_END => self.seek = min(0, max(self.data.len() as isize, self.data.len() as isize + offset as isize)) as usize,
            _ => return Err(Error::new(EINVAL))
        }
        Ok(self.seek)
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

    fn stat(&self, stat: &mut Stat) -> Result<usize> {
        stat.st_mode = MODE_DIR;
        stat.st_size = self.data.len() as u64;
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
    size: u64,
}

impl FileResource {
    pub fn new(path: &str, block: u64, size: u64) -> FileResource {
        FileResource {
            path: path.to_string(),
            block: block,
            seek: 0,
            size: size,
        }
    }
}

impl Resource for FileResource {
    fn read(&mut self, buf: &mut [u8], fs: &mut FileSystem) -> Result<usize> {
        let count = try!(fs.read_node(self.block, self.seek, buf));
        self.seek += count as u64;
        Ok(count)
    }

    fn write(&mut self, buf: &[u8], fs: &mut FileSystem) -> Result<usize> {
        let count = try!(fs.write_node(self.block, self.seek, buf));
        self.seek += count as u64;
        if self.seek > self.size {
            self.size = self.seek;
        }
        Ok(count)
    }

    fn seek(&mut self, offset: usize, whence: usize) -> Result<usize> {
        match whence {
            SEEK_SET => self.seek = min(0, max(self.size as i64, offset as i64)) as u64,
            SEEK_CUR => self.seek = min(0, max(self.size as i64, self.seek as i64 + offset as i64)) as u64,
            SEEK_END => self.seek = min(0, max(self.size as i64, self.size as i64 + offset as i64)) as u64,
            _ => return Err(Error::new(EINVAL))
        }

        Ok(self.seek as usize)
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

    fn stat(&self, stat: &mut Stat) -> Result<usize> {
        stat.st_mode = MODE_FILE;
        stat.st_size = self.size;
        Ok(0)
    }

    fn sync(&mut self) -> Result<usize> {
        Ok(0)
    }

    fn truncate(&mut self, len: usize, fs: &mut FileSystem) -> Result<usize> {
        fs.node_set_len(self.block, len as u64).and(Ok(0))
    }
}
