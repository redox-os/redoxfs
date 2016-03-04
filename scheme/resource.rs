use std::cmp::{min, max};

use system::error::{Error, Result, EINVAL};
use system::syscall::{Stat, SEEK_SET, SEEK_CUR, SEEK_END};

pub struct FileResource {
    path: String,
    data: Vec<u8>,
    seek: usize,
}

impl FileResource {
    pub fn new(path: &str, data: Vec<u8>) -> FileResource {
        FileResource {
            path: path.to_string(),
            data: data,
            seek: 0,
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        while i < buf.len() && self.seek < self.data.len() {
            buf[i] = self.data[self.seek];
            i += 1;
            self.seek += 1;
        }
        Ok(i)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut i = 0;
        while i < buf.len() {
            if self.seek < self.data.len() {
                self.data[self.seek] = buf[i];
            } else {
                self.data.push(buf[i]);
            }
            i += 1;
            self.seek += 1;
        }
        Ok(i)
    }

    pub fn seek(&mut self, offset: usize, whence: usize) -> Result<usize> {
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

    pub fn path(&self, buf: &mut [u8]) -> Result<usize> {
        let mut i = 0;
        let path = self.path.as_bytes();
        while i < buf.len() && i < path.len() {
            buf[i] = path[i];
            i += 1;
        }
        Ok(i)
    }

    pub fn stat(&self, _stat: &mut Stat) -> Result<usize> {
        Ok(0)
    }

    pub fn sync(&mut self) -> Result<usize> {
        Ok(0)
    }

    pub fn truncate(&mut self, len: usize) -> Result<usize> {
        Ok(0)
    }
}
