use std::cmp::{max, min};
use std::collections::BTreeMap;
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};

use syscall::data::{Map, Stat, TimeSpec};
use syscall::error::{Error, Result, EBADF, EINVAL, EISDIR, ENOMEM, EPERM};
use syscall::flag::{
    F_GETFL, F_SETFL, MODE_PERM, O_ACCMODE, O_APPEND, O_RDONLY, O_RDWR, O_WRONLY, PROT_READ,
    PROT_WRITE, SEEK_CUR, SEEK_END, SEEK_SET, MapFlags,
};

use disk::Disk;
use filesystem::FileSystem;

pub trait Resource<D: Disk> {
    fn block(&self) -> u64;
    fn dup(&self) -> Result<Box<Resource<D>>>;
    fn set_path(&mut self, path: &str);
    fn read(&mut self, buf: &mut [u8], fs: &mut FileSystem<D>) -> Result<usize>;
    fn write(&mut self, buf: &[u8], fs: &mut FileSystem<D>) -> Result<usize>;
    fn seek(&mut self, offset: isize, whence: usize, fs: &mut FileSystem<D>) -> Result<isize>;
    fn fmap(&mut self, map: &Map, fs: &mut FileSystem<D>) -> Result<usize>;
    fn funmap(&mut self, address: usize, fs: &mut FileSystem<D>) -> Result<usize>;
    fn fchmod(&mut self, mode: u16, fs: &mut FileSystem<D>) -> Result<usize>;
    fn fchown(&mut self, uid: u32, gid: u32, fs: &mut FileSystem<D>) -> Result<usize>;
    fn fcntl(&mut self, cmd: usize, arg: usize) -> Result<usize>;
    fn path(&self, buf: &mut [u8]) -> Result<usize>;
    fn stat(&self, _stat: &mut Stat, fs: &mut FileSystem<D>) -> Result<usize>;
    fn sync(&mut self, fs: &mut FileSystem<D>) -> Result<usize>;
    fn truncate(&mut self, len: usize, fs: &mut FileSystem<D>) -> Result<usize>;
    fn utimens(&mut self, times: &[TimeSpec], fs: &mut FileSystem<D>) -> Result<usize>;
}

pub struct DirResource {
    path: String,
    block: u64,
    data: Option<Vec<u8>>,
    seek: isize,
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
            uid: self.uid,
        }))
    }

    fn set_path(&mut self, path: &str) {
        self.path = path.to_string();
    }

    fn read(&mut self, buf: &mut [u8], _fs: &mut FileSystem<D>) -> Result<usize> {
        let data = self.data.as_ref().ok_or(Error::new(EISDIR))?;
        let size = data.len() as isize;
        let mut i = 0;
        while i < buf.len() && self.seek < size {
            buf[i] = data[self.seek as usize];
            i += 1;
            self.seek += 1;
        }
        Ok(i)
    }

    fn write(&mut self, _buf: &[u8], _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn seek(&mut self, offset: isize, whence: usize, _fs: &mut FileSystem<D>) -> Result<isize> {
        let data = self.data.as_ref().ok_or(Error::new(EBADF))?;
        let size = data.len() as isize;
        self.seek = match whence {
            SEEK_SET => max(0, min(size, offset)),
            SEEK_CUR => max(0, min(size, self.seek + offset)),
            SEEK_END => max(0, min(size, size + offset)),
            _ => return Err(Error::new(EINVAL)),
        };
        Ok(self.seek)
    }

    fn fmap(&mut self, _map: &Map, _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn funmap(&mut self, _address: usize, _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn fchmod(&mut self, mode: u16, fs: &mut FileSystem<D>) -> Result<usize> {
        let mut node = fs.node(self.block)?;

        if node.1.uid == self.uid || self.uid == 0 {
            node.1.mode = (node.1.mode & !MODE_PERM) | (mode & MODE_PERM);

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
            st_atime: node.1.atime,
            st_atime_nsec: node.1.atime_nsec,
            st_ctime: node.1.ctime,
            st_ctime_nsec: node.1.ctime_nsec,
            ..Default::default()
        };

        Ok(0)
    }

    fn sync(&mut self, _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn truncate(&mut self, _len: usize, _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn utimens(&mut self, _times: &[TimeSpec], _fs: &mut FileSystem<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }
}

pub struct Fmap {
    block: u64,
    offset: usize,
    flags: MapFlags,
    data: &'static mut [u8],
}

impl Fmap {
    pub unsafe fn new<D: Disk>(block: u64, map: &Map, fs: &mut FileSystem<D>) -> Result<Self> {
        extern "C" {
            fn memalign(align: usize, size: usize) -> *mut u8;
            fn free(ptr: *mut u8);
        }

        // Memory provided to fmap must be page aligned and sized
        let align = 4096;
        let address = memalign(align, ((map.size + align - 1) / align) * align);
        if address.is_null() {
            return Err(Error::new(ENOMEM));
        }

        // Read buffer from disk
        let buf = slice::from_raw_parts_mut(address, map.size);
        let count = match fs.read_node(block, map.offset as u64, buf) {
            Ok(ok) => ok,
            Err(err) => {
                free(address);
                return Err(err);
            }
        };

        // Make sure remaining data is zeroed
        for i in count..buf.len() {
            buf[i] = 0;
        }

        Ok(Self {
            block,
            offset: map.offset,
            flags: map.flags,
            data: buf,
        })
    }

    pub fn sync<D: Disk>(&mut self, fs: &mut FileSystem<D>) -> Result<()> {
        if self.flags & PROT_WRITE == PROT_WRITE {
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            fs.write_node(
                self.block,
                self.offset as u64,
                &self.data,
                mtime.as_secs(),
                mtime.subsec_nanos(),
            )?;
        }
        Ok(())
    }
}

impl Drop for Fmap {
    fn drop(&mut self) {
        unsafe {
            extern "C" {
                fn free(ptr: *mut u8);
            }

            free(self.data.as_mut_ptr());
        }
    }
}

pub struct FileResource {
    path: String,
    block: u64,
    flags: usize,
    seek: isize,
    uid: u32,
    fmaps: BTreeMap<usize, Fmap>,
}

impl FileResource {
    pub fn new(path: String, block: u64, flags: usize, uid: u32) -> FileResource {
        FileResource {
            path,
            block,
            flags,
            seek: 0,
            uid,
            fmaps: BTreeMap::new(),
        }
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
            fmaps: BTreeMap::new(),
        }))
    }

    fn set_path(&mut self, path: &str) {
        self.path = path.to_string();
    }

    fn read(&mut self, buf: &mut [u8], fs: &mut FileSystem<D>) -> Result<usize> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_RDONLY {
            let count = fs.read_node(self.block, self.seek as u64, buf)?;
            self.seek += count as isize;
            Ok(count)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn write(&mut self, buf: &[u8], fs: &mut FileSystem<D>) -> Result<usize> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_WRONLY {
            if self.flags & O_APPEND == O_APPEND {
                self.seek = fs.node_len(self.block)? as isize;
            }
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let count = fs.write_node(
                self.block,
                self.seek as u64,
                buf,
                mtime.as_secs(),
                mtime.subsec_nanos(),
            )?;
            self.seek += count as isize;
            Ok(count)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn seek(&mut self, offset: isize, whence: usize, fs: &mut FileSystem<D>) -> Result<isize> {
        let size = fs.node_len(self.block)? as isize;
        self.seek = match whence {
            SEEK_SET => max(0, offset),
            SEEK_CUR => max(0, self.seek + offset),
            SEEK_END => max(0, size + offset),
            _ => return Err(Error::new(EINVAL)),
        };
        Ok(self.seek)
    }

    fn fmap(&mut self, map: &Map, fs: &mut FileSystem<D>) -> Result<usize> {
        let accmode = self.flags & O_ACCMODE;
        if map.flags.contains(PROT_READ) && !(accmode == O_RDWR || accmode == O_RDONLY) {
            return Err(Error::new(EBADF));
        }
        if map.flags.contains(PROT_WRITE) && !(accmode == O_RDWR || accmode == O_WRONLY) {
            return Err(Error::new(EBADF));
        }
        //TODO: PROT_EXEC?

        let map = unsafe { Fmap::new(self.block, map, fs)? };
        let address = map.data.as_ptr() as usize;
        self.fmaps.insert(address, map);
        Ok(address)
    }

    fn funmap(&mut self, address: usize, fs: &mut FileSystem<D>) -> Result<usize> {
        if let Some(mut fmap) = self.fmaps.remove(&address) {
            fmap.sync(fs)?;

            Ok(0)
        } else {
            Err(Error::new(EINVAL))
        }
    }

    fn fchmod(&mut self, mode: u16, fs: &mut FileSystem<D>) -> Result<usize> {
        let mut node = fs.node(self.block)?;

        if node.1.uid == self.uid || self.uid == 0 {
            node.1.mode = (node.1.mode & !MODE_PERM) | (mode & MODE_PERM);

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
                self.flags = (self.flags & O_ACCMODE) | (arg & !O_ACCMODE);
                Ok(0)
            }
            _ => Err(Error::new(EINVAL)),
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
            st_atime: node.1.atime,
            st_atime_nsec: node.1.atime_nsec,
            st_ctime: node.1.ctime,
            st_ctime_nsec: node.1.ctime_nsec,
            ..Default::default()
        };

        Ok(0)
    }

    fn sync(&mut self, fs: &mut FileSystem<D>) -> Result<usize> {
        for fmap in self.fmaps.values_mut() {
            fmap.sync(fs)?;
        }

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
            if let &[atime, mtime] = times {
                node.1.mtime = mtime.tv_sec as u64;
                node.1.mtime_nsec = mtime.tv_nsec as u32;
                node.1.atime = atime.tv_sec as u64;
                node.1.atime_nsec = atime.tv_nsec as u32;

                fs.write_at(node.0, &node.1)?;
            }
            Ok(0)
        } else {
            Err(Error::new(EPERM))
        }
    }
}

impl Drop for FileResource {
    fn drop(&mut self) {
        if !self.fmaps.is_empty() {
            eprintln!(
                "redoxfs: file {} still has {} fmaps!",
                self.path,
                self.fmaps.len()
            );
        }
    }
}
