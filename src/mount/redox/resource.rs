use std::cmp::{min, max};
use std::time::{SystemTime, UNIX_EPOCH};

use syscall::data::TimeSpec;
use syscall::error::{Error, Result, EBADF, EBUSY, EINVAL, EISDIR, EPERM};
use syscall::flag::{O_ACCMODE, O_APPEND, O_RDONLY, O_WRONLY, O_RDWR, F_GETFL, F_SETFL, MODE_PERM};
use syscall::{Stat, SEEK_SET, SEEK_CUR, SEEK_END};

use disk::Disk;
use filesystem::FileSystem;
use super::scheme::{Fmaps, FmapKey, FmapValue};

pub trait Resource<D: Disk> {
    fn block(&self) -> u64;
    fn dup(&self) -> Result<Box<Resource<D>>>;
    fn read(&mut self, buf: &mut [u8], fs: &mut FileSystem<D>) -> Result<usize>;
    fn write(&mut self, buf: &[u8], fs: &mut FileSystem<D>) -> Result<usize>;
    fn seek(&mut self, offset: usize, whence: usize, fs: &mut FileSystem<D>) -> Result<usize>;
    fn fmap(&mut self, offset: usize, size: usize, maps: &mut Fmaps, fs: &mut FileSystem<D>) -> Result<usize>;
    fn funmap(&mut self, maps: &mut Fmaps, fs: &mut FileSystem<D>) -> Result<usize>;
    fn fchmod(&mut self, mode: u16, fs: &mut FileSystem<D>) -> Result<usize>;
    fn fchown(&mut self, uid: u32, gid: u32, fs: &mut FileSystem<D>) -> Result<usize>;
    fn fcntl(&mut self, cmd: usize, arg: usize) -> Result<usize>;
    fn path(&self, buf: &mut [u8]) -> Result<usize>;
    fn stat(&self, _stat: &mut Stat, fs: &mut FileSystem<D>) -> Result<usize>;
    fn sync(&mut self, maps: &mut Fmaps, fs: &mut FileSystem<D>) -> Result<usize>;
    fn truncate(&mut self, len: usize, fs: &mut FileSystem<D>) -> Result<usize>;
    fn utimens(&mut self, times: &[TimeSpec], fs: &mut FileSystem<D>) -> Result<usize>;
}

pub struct DirResource {
    path: String,
    block: u64,
    data: Option<Vec<u8>>,
    seek: usize,
    uid: u32,
}

impl DirResource {
    pub fn new(path: String, block: u64, data: Option<Vec<u8>>, uid: u32) -> DirResource {
        DirResource {
            path: path,
            block: block,
            data: data,
            seek: 0,
            uid: uid,
        }
    }
}

impl<D: Disk> Resource<D> for DirResource {
    fn block(&self) -> u64 {
        self.block
    }

    fn dup(&self) -> Result<Box<Resource<D>>> {
        Ok(Box::new(DirResource {
            path: self.path.clone(),
            block: self.block,
            data: self.data.clone(),
            seek: self.seek,
            uid: self.uid
        }))
    }

    fn read(&mut self, buf: &mut [u8], _fs: &mut FileSystem<D>) -> Result<usize> {
        let data = self.data.as_ref().ok_or(Error::new(EISDIR))?;
        let mut i = 0;
        while i < buf.len() && self.seek < data.len() {
            buf[i] = data[self.seek];
            i += 1;
            self.seek += 1;
        }
        Ok(i)
    }

    fn write(&mut self, _buf: &[u8], _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn seek(&mut self, offset: usize, whence: usize, _fs: &mut FileSystem<D>) -> Result<usize> {
        let data = self.data.as_ref().ok_or(Error::new(EBADF))?;
        self.seek = match whence {
            SEEK_SET => max(0, min(data.len() as isize, offset as isize)) as usize,
            SEEK_CUR => max(0, min(data.len() as isize, self.seek as isize + offset as isize)) as usize,
            SEEK_END => max(0, min(data.len() as isize, data.len() as isize + offset as isize)) as usize,
            _ => return Err(Error::new(EINVAL))
        };

        Ok(self.seek)
    }

    fn fmap(&mut self, _offset: usize, _size: usize, _maps: &mut Fmaps, _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn funmap(&mut self, _maps: &mut Fmaps, _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn fchmod(&mut self, mode: u16, fs: &mut FileSystem<D>) -> Result<usize> {
        let mut node = fs.node(self.block)?;

        if node.1.uid == self.uid || self.uid == 0 {
            node.1.mode = (node.1.mode & ! MODE_PERM) | (mode & MODE_PERM);

            fs.write_at(node.0, &node.1)?;

            Ok(0)
        } else {
            Err(Error::new(EPERM))
        }
    }

    fn fchown(&mut self, uid: u32, gid: u32, fs: &mut FileSystem<D>) -> Result<usize> {
        let mut node = fs.node(self.block)?;

        if node.1.uid == self.uid || self.uid == 0 {
            if uid as i32 != -1 {
                node.1.uid = uid;
            }

            if gid as i32 != -1 {
                node.1.gid = gid;
            }

            fs.write_at(node.0, &node.1)?;

            Ok(0)
        } else {
            Err(Error::new(EPERM))
        }
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

    fn stat(&self, stat: &mut Stat, fs: &mut FileSystem<D>) -> Result<usize> {
        let node = fs.node(self.block)?;

        *stat = Stat {
            st_dev: 0, // TODO
            st_ino: node.0,
            st_mode: node.1.mode,
            st_nlink: 1,
            st_uid: node.1.uid,
            st_gid: node.1.gid,
            st_size: fs.node_len(self.block)?,
            st_mtime: node.1.mtime,
            st_mtime_nsec: node.1.mtime_nsec,
            st_ctime: node.1.ctime,
            st_ctime_nsec: node.1.ctime_nsec,
            ..Default::default()
        };

        Ok(0)
    }

    fn sync(&mut self, _maps: &mut Fmaps, _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn truncate(&mut self, _len: usize, _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn utimens(&mut self, _times: &[TimeSpec], _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }
}

pub struct FileResource {
    path: String,
    block: u64,
    flags: usize,
    seek: u64,
    uid: u32,
    fmap: Option<(usize, FmapKey)>
}

impl FileResource {
    pub fn new(path: String, block: u64, flags: usize, uid: u32) -> FileResource {
        FileResource {
            path,
            block,
            flags,
            seek: 0,
            uid,
            fmap: None
        }
    }

    fn sync_fmap<D: Disk>(&mut self, maps: &mut Fmaps, fs: &mut FileSystem<D>) -> Result<()> {
        if let Some((i, key_exact)) = self.fmap.as_ref() {
            let (key_round, value) = maps.index(*i).as_mut().expect("mapping dropped while still referenced");

            let rel_offset = key_exact.offset - key_round.offset;
            // Minimum out of our size and the original file size
            let actual_size = (value.actual_size - rel_offset).min(key_exact.size);

            let mut count = 0;
            while count < actual_size {
                let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                match fs.write_node(self.block, key_exact.offset as u64 + count as u64,
                        &value.buffer[rel_offset..][count..actual_size],
                        mtime.as_secs(), mtime.subsec_nanos())? {
                    0 => {
                        eprintln!("Fmap failed to write whole buffer, encountered EOF early.");
                        break;
                    }
                    n => count += n,
                }
            }
        }
        Ok(())
    }
}

impl<D: Disk> Resource<D> for FileResource {
    fn block(&self) -> u64 {
        self.block
    }

    fn dup(&self) -> Result<Box<Resource<D>>> {
        Ok(Box::new(FileResource {
            path: self.path.clone(),
            block: self.block,
            flags: self.flags,
            seek: self.seek,
            uid: self.uid,
            fmap: None
        }))
    }

    fn read(&mut self, buf: &mut [u8], fs: &mut FileSystem<D>) -> Result<usize> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_RDONLY {
            let count = fs.read_node(self.block, self.seek, buf)?;
            self.seek += count as u64;
            Ok(count)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn write(&mut self, buf: &[u8], fs: &mut FileSystem<D>) -> Result<usize> {
        if self.flags & O_WRONLY == O_WRONLY {
            if self.flags & O_APPEND == O_APPEND {
                self.seek = fs.node_len(self.block)?;
            }
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let count = fs.write_node(self.block, self.seek, buf, mtime.as_secs(), mtime.subsec_nanos())?;
            self.seek += count as u64;
            Ok(count)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn seek(&mut self, offset: usize, whence: usize, fs: &mut FileSystem<D>) -> Result<usize> {
        let size = fs.node_len(self.block)?;

        self.seek = match whence {
            SEEK_SET => max(0, offset as i64) as u64,
            SEEK_CUR => max(0, self.seek as i64 + offset as i64) as u64,
            SEEK_END => max(0, size as i64 + offset as i64) as u64,
            _ => return Err(Error::new(EINVAL))
        };

        Ok(self.seek as usize)
    }

    fn fmap(&mut self, offset: usize, size: usize, maps: &mut Fmaps, fs: &mut FileSystem<D>) -> Result<usize> {
        if self.flags & O_ACCMODE == O_RDWR {
            let key_exact = FmapKey {
                block: self.block,
                offset,
                size
            };

            let i = match maps.find_compatible(&key_exact) {
                Ok((i, (key_existing, value))) => {
                    value.refcount += 1;
                    self.fmap = Some((i, key_exact));
                    return Ok(value.buffer.as_ptr() as usize + (key_exact.offset - key_existing.offset))
                },
                Err(None) => {
                    // This is bad!
                    // We reached the limit of maps, and we can't reallocate
                    // because that would invalidate stuff.
                    // Sorry, nothing personal :(
                    return Err(Error::new(EBUSY))
                },
                Err(Some(i)) => {
                    // Can't do stuff in here because lifetime issues
                    i
                }
            };
            let key_round = key_exact.round();

            let mut content = vec![0; key_round.size];
            let mut count = 0;
            while count < key_round.size {
                match fs.read_node(self.block, key_round.offset as u64 + count as u64,
                        &mut content[key_round.offset..][count..key_round.size])? {
                    0 => break,
                    n => count += n
                }
            }

            let value = maps.insert(i, key_round, FmapValue {
                buffer: content,
                actual_size: count,
                refcount: 1
            });

            self.fmap = Some((i, key_exact));
            Ok(value.buffer.as_ptr() as usize + (key_exact.offset - key_round.offset))
        } else {
            Err(Error::new(EBADF))
        }
    }
    fn funmap(&mut self, maps: &mut Fmaps, fs: &mut FileSystem<D>) -> Result<usize> {
        self.sync_fmap(maps, fs)?;
        if let Some((i, _)) = self.fmap.as_ref() {
            let value = maps.index(*i);
            let clear = {
                let (_, value) = value.as_mut().expect("mapping dropped while still referenced");
                value.refcount -= 1;
                value.refcount == 0
            };
            if clear {
                *value = None;
            }
        }
        Ok(0)
    }

    fn fchmod(&mut self, mode: u16, fs: &mut FileSystem<D>) -> Result<usize> {
        let mut node = fs.node(self.block)?;

        if node.1.uid == self.uid || self.uid == 0 {
            node.1.mode = (node.1.mode & ! MODE_PERM) | (mode & MODE_PERM);

            fs.write_at(node.0, &node.1)?;

            Ok(0)
        } else {
            Err(Error::new(EPERM))
        }
    }

    fn fchown(&mut self, uid: u32, gid: u32, fs: &mut FileSystem<D>) -> Result<usize> {
        let mut node = fs.node(self.block)?;

        if node.1.uid == self.uid || self.uid == 0 {
            if uid as i32 != -1 {
                node.1.uid = uid;
            }

            if gid as i32 != -1 {
                node.1.gid = gid;
            }

            fs.write_at(node.0, &node.1)?;

            Ok(0)
        } else {
            Err(Error::new(EPERM))
        }
    }

    fn fcntl(&mut self, cmd: usize, arg: usize) -> Result<usize> {
        match cmd {
            F_GETFL => Ok(self.flags),
            F_SETFL => {
                self.flags = (self.flags & O_ACCMODE) | (arg & ! O_ACCMODE);
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

    fn stat(&self, stat: &mut Stat, fs: &mut FileSystem<D>) -> Result<usize> {
        let node = fs.node(self.block)?;

        *stat = Stat {
            st_dev: 0, // TODO
            st_ino: node.0,
            st_mode: node.1.mode,
            st_nlink: 1,
            st_uid: node.1.uid,
            st_gid: node.1.gid,
            st_size: fs.node_len(self.block)?,
            st_mtime: node.1.mtime,
            st_mtime_nsec: node.1.mtime_nsec,
            st_ctime: node.1.ctime,
            st_ctime_nsec: node.1.ctime_nsec,
            ..Default::default()
        };

        Ok(0)
    }

    fn sync(&mut self, maps: &mut Fmaps, fs: &mut FileSystem<D>) -> Result<usize> {
        self.sync_fmap(maps, fs)?;
        Ok(0)
    }

    fn truncate(&mut self, len: usize, fs: &mut FileSystem<D>) -> Result<usize> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_WRONLY {
            fs.node_set_len(self.block, len as u64)?;
            Ok(0)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn utimens(&mut self, times: &[TimeSpec], fs: &mut FileSystem<D>) -> Result<usize> {
        let mut node = fs.node(self.block)?;

        if node.1.uid == self.uid || self.uid == 0 {
            if let Some(mtime) = times.get(1) {

                node.1.mtime = mtime.tv_sec as u64;
                node.1.mtime_nsec = mtime.tv_nsec as u32;

                fs.write_at(node.0, &node.1)?;

                Ok(0)
            } else {
                Ok(0)
            }
        } else {
            Err(Error::new(EPERM))
        }
    }
}
