use redoxfs::FileSystem;

use std::cmp::{min, max};
use std::time::{SystemTime, UNIX_EPOCH};

use syscall::error::{Error, Result, EBADF, EINVAL};
use syscall::flag::{O_ACCMODE, O_RDONLY, O_WRONLY, O_RDWR, F_GETFL, F_SETFL};
use syscall::{Stat, SEEK_SET, SEEK_CUR, SEEK_END};

pub trait Resource {
    fn dup(&self) -> Result<Box<Resource>>;
    fn read(&mut self, buf: &mut [u8], fs: &mut FileSystem) -> Result<usize>;
    fn write(&mut self, buf: &[u8], fs: &mut FileSystem) -> Result<usize>;
    fn seek(&mut self, offset: usize, whence: usize, fs: &mut FileSystem) -> Result<usize>;
    fn fcntl(&mut self, cmd: usize, arg: usize) -> Result<usize>;
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
        Err(Error::new(EBADF))
    }

    fn seek(&mut self, offset: usize, whence: usize, _fs: &mut FileSystem) -> Result<usize> {
        self.seek = match whence {
            SEEK_SET => max(0, min(self.data.len() as isize, offset as isize)) as usize,
            SEEK_CUR => max(0, min(self.data.len() as isize, self.seek as isize + offset as isize)) as usize,
            SEEK_END => max(0, min(self.data.len() as isize, self.data.len() as isize + offset as isize)) as usize,
            _ => return Err(Error::new(EINVAL))
        };

        Ok(self.seek)
    }

    fn fcntl(&mut self, _cmd: usize, _arg: usize) -> Result<usize> {
        Err(Error::new(EBADF))
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
        let node = fs.node(self.block)?;

        *stat = Stat {
            st_dev: 0, // TODO
            st_ino: node.0,
            st_mode: node.1.mode,
            st_uid: node.1.uid,
            st_gid: node.1.gid,
            st_size: fs.node_len(self.block)?,
            ..Default::default()
        };

        Ok(0)
    }

    fn sync(&mut self) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn truncate(&mut self, _len: usize, _fs: &mut FileSystem) -> Result<usize> {
        Err(Error::new(EBADF))
    }
}

pub struct FileResource {
    path: String,
    block: u64,
    flags: usize,
    seek: u64,
}

impl FileResource {
    pub fn new(path: String, block: u64, flags: usize, seek: u64) -> FileResource {
        FileResource {
            path: path,
            block: block,
            flags: flags,
            seek: seek,
        }
    }
}

impl Resource for FileResource {
    fn dup(&self) -> Result<Box<Resource>> {
        Ok(Box::new(FileResource {
            path: self.path.clone(),
            block: self.block,
            flags: self.flags,
            seek: self.seek,
        }))
    }

    fn read(&mut self, buf: &mut [u8], fs: &mut FileSystem) -> Result<usize> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_RDONLY {
            let count = fs.read_node(self.block, self.seek, buf)?;
            self.seek += count as u64;
            Ok(count)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn write(&mut self, buf: &[u8], fs: &mut FileSystem) -> Result<usize> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_WRONLY {
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let count = fs.write_node(self.block, self.seek, buf, mtime.as_secs(), mtime.subsec_nanos())?;
            self.seek += count as u64;
            Ok(count)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn seek(&mut self, offset: usize, whence: usize, fs: &mut FileSystem) -> Result<usize> {
        let size = fs.node_len(self.block)?;

        self.seek = match whence {
            SEEK_SET => max(0, offset as i64) as u64,
            SEEK_CUR => max(0, self.seek as i64 + offset as i64) as u64,
            SEEK_END => max(0, size as i64 + offset as i64) as u64,
            _ => return Err(Error::new(EINVAL))
        };

        Ok(self.seek as usize)
    }

    fn fcntl(&mut self, cmd: usize, arg: usize) -> Result<usize> {
        match cmd {
            F_GETFL => Ok(self.flags),
            F_SETFL => {
                self.flags = arg & ! O_ACCMODE;
                Ok(0)
            },
            _ => Err(Error::new(EINVAL))
        }
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
        let node = fs.node(self.block)?;

        *stat = Stat {
            st_dev: 0, // TODO
            st_ino: node.0,
            st_mode: node.1.mode,
            st_uid: node.1.uid,
            st_gid: node.1.gid,
            st_size: fs.node_len(self.block)?,
            ..Default::default()
        };

        Ok(0)
    }

    fn sync(&mut self) -> Result<usize> {
        Ok(0)
    }

    fn truncate(&mut self, len: usize, fs: &mut FileSystem) -> Result<usize> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_WRONLY {
            fs.node_set_len(self.block, len as u64)?;
            Ok(0)
        } else {
            Err(Error::new(EBADF))
        }
    }
}
