use std::cmp::{max, min};
use std::collections::BTreeMap;
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};

use syscall::data::{Map, Stat, TimeSpec};
use syscall::error::{Error, Result, EBADF, EINVAL, EISDIR, ENOMEM, EPERM};
use syscall::flag::{
    MapFlags, F_GETFL, F_SETFL, MODE_PERM, O_ACCMODE, O_APPEND, O_RDONLY, O_RDWR, O_WRONLY,
    PROT_READ, PROT_WRITE, SEEK_CUR, SEEK_END, SEEK_SET,
};

use crate::{Disk, Node, Transaction, TreePtr};

pub trait Resource<D: Disk> {
    fn parent_ptr_opt(&self) -> Option<TreePtr<Node>>;

    fn node_ptr(&self) -> TreePtr<Node>;

    fn uid(&self) -> u32;

    fn dup(&self) -> Result<Box<dyn Resource<D>>>;

    fn set_path(&mut self, path: &str);

    fn read(&mut self, buf: &mut [u8], tx: &mut Transaction<D>) -> Result<usize>;

    fn write(&mut self, buf: &[u8], tx: &mut Transaction<D>) -> Result<usize>;

    fn seek(&mut self, offset: isize, whence: usize, tx: &mut Transaction<D>) -> Result<isize>;

    fn fmap(&mut self, map: &Map, tx: &mut Transaction<D>) -> Result<usize>;

    fn funmap(&mut self, address: usize, tx: &mut Transaction<D>) -> Result<usize>;

    fn fchmod(&mut self, mode: u16, tx: &mut Transaction<D>) -> Result<usize> {
        let mut node = tx.read_tree(self.node_ptr())?;

        if node.data().uid() == self.uid() || self.uid() == 0 {
            let old_mode = node.data().mode();
            let new_mode = (old_mode & !MODE_PERM) | (mode & MODE_PERM);
            if old_mode != new_mode {
                node.data_mut().set_mode(new_mode);
                tx.sync_tree(node)?;
            }

            Ok(0)
        } else {
            Err(Error::new(EPERM))
        }
    }

    fn fchown(&mut self, uid: u32, gid: u32, tx: &mut Transaction<D>) -> Result<usize> {
        let mut node = tx.read_tree(self.node_ptr())?;

        let old_uid = node.data().uid();
        if old_uid == self.uid() || self.uid() == 0 {
            let mut node_changed = false;

            if uid as i32 != -1 {
                if uid != old_uid {
                    node.data_mut().set_uid(uid);
                    node_changed = true;
                }
            }

            if gid as i32 != -1 {
                let old_gid = node.data().gid();
                if gid != old_gid {
                    node.data_mut().set_gid(gid);
                    node_changed = true;
                }
            }

            if node_changed {
                tx.sync_tree(node)?;
            }

            Ok(0)
        } else {
            Err(Error::new(EPERM))
        }
    }

    fn fcntl(&mut self, cmd: usize, arg: usize) -> Result<usize>;

    fn path(&self) -> &str;

    fn stat(&self, stat: &mut Stat, tx: &mut Transaction<D>) -> Result<usize> {
        let node = tx.read_tree(self.node_ptr())?;

        let ctime = node.data().ctime();
        let mtime = node.data().mtime();
        let atime = node.data().atime();
        *stat = Stat {
            st_dev: 0, // TODO
            st_ino: node.id() as u64,
            st_mode: node.data().mode(),
            st_nlink: node.data().links(),
            st_uid: node.data().uid(),
            st_gid: node.data().gid(),
            st_size: node.data().size(),
            st_mtime: mtime.0,
            st_mtime_nsec: mtime.1,
            st_atime: atime.0,
            st_atime_nsec: atime.1,
            st_ctime: ctime.0,
            st_ctime_nsec: ctime.1,
            ..Default::default()
        };

        Ok(0)
    }

    fn sync(&mut self, tx: &mut Transaction<D>) -> Result<usize>;

    fn truncate(&mut self, len: usize, tx: &mut Transaction<D>) -> Result<usize>;

    fn utimens(&mut self, times: &[TimeSpec], tx: &mut Transaction<D>) -> Result<usize>;
}

pub struct DirResource {
    path: String,
    parent_ptr_opt: Option<TreePtr<Node>>,
    node_ptr: TreePtr<Node>,
    data: Option<Vec<u8>>,
    seek: isize,
    uid: u32,
}

impl DirResource {
    pub fn new(
        path: String,
        parent_ptr_opt: Option<TreePtr<Node>>,
        node_ptr: TreePtr<Node>,
        data: Option<Vec<u8>>,
        uid: u32,
    ) -> DirResource {
        DirResource {
            path,
            parent_ptr_opt,
            node_ptr,
            data,
            seek: 0,
            uid,
        }
    }
}

impl<D: Disk> Resource<D> for DirResource {
    fn parent_ptr_opt(&self) -> Option<TreePtr<Node>> {
        self.parent_ptr_opt
    }

    fn node_ptr(&self) -> TreePtr<Node> {
        self.node_ptr
    }

    fn uid(&self) -> u32 {
        self.uid
    }

    fn dup(&self) -> Result<Box<dyn Resource<D>>> {
        Ok(Box::new(DirResource {
            path: self.path.clone(),
            parent_ptr_opt: self.parent_ptr_opt,
            node_ptr: self.node_ptr,
            data: self.data.clone(),
            seek: self.seek,
            uid: self.uid,
        }))
    }

    fn set_path(&mut self, path: &str) {
        self.path = path.to_string();
    }

    fn read(&mut self, buf: &mut [u8], _tx: &mut Transaction<D>) -> Result<usize> {
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

    fn write(&mut self, _buf: &[u8], _tx: &mut Transaction<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn seek(&mut self, offset: isize, whence: usize, _tx: &mut Transaction<D>) -> Result<isize> {
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

    fn fmap(&mut self, _map: &Map, _tx: &mut Transaction<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn funmap(&mut self, _address: usize, _tx: &mut Transaction<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn fcntl(&mut self, _cmd: usize, _arg: usize) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn sync(&mut self, _tx: &mut Transaction<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn truncate(&mut self, _len: usize, _tx: &mut Transaction<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn utimens(&mut self, _times: &[TimeSpec], _tx: &mut Transaction<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }
}

pub struct Fmap {
    node_ptr: TreePtr<Node>,
    offset: usize,
    flags: MapFlags,
    data: &'static mut [u8],
}

impl Fmap {
    pub unsafe fn new<D: Disk>(
        node_ptr: TreePtr<Node>,
        map: &Map,
        tx: &mut Transaction<D>,
    ) -> Result<Self> {
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
        let atime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let buf = slice::from_raw_parts_mut(address, map.size);
        let count = match tx.read_node(
            node_ptr,
            map.offset as u64,
            buf,
            atime.as_secs(),
            atime.subsec_nanos(),
        ) {
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
            node_ptr,
            offset: map.offset,
            flags: map.flags,
            data: buf,
        })
    }

    pub fn sync<D: Disk>(&mut self, tx: &mut Transaction<D>) -> Result<()> {
        if self.flags & PROT_WRITE == PROT_WRITE {
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            tx.write_node(
                self.node_ptr,
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
    parent_ptr_opt: Option<TreePtr<Node>>,
    node_ptr: TreePtr<Node>,
    flags: usize,
    seek: isize,
    uid: u32,
    fmaps: BTreeMap<usize, Fmap>,
}

impl FileResource {
    pub fn new(
        path: String,
        parent_ptr_opt: Option<TreePtr<Node>>,
        node_ptr: TreePtr<Node>,
        flags: usize,
        uid: u32,
    ) -> FileResource {
        FileResource {
            path,
            parent_ptr_opt,
            node_ptr,
            flags,
            seek: 0,
            uid,
            fmaps: BTreeMap::new(),
        }
    }
}

impl<D: Disk> Resource<D> for FileResource {
    fn parent_ptr_opt(&self) -> Option<TreePtr<Node>> {
        self.parent_ptr_opt
    }

    fn node_ptr(&self) -> TreePtr<Node> {
        self.node_ptr
    }

    fn uid(&self) -> u32 {
        self.uid
    }

    fn dup(&self) -> Result<Box<dyn Resource<D>>> {
        Ok(Box::new(FileResource {
            path: self.path.clone(),
            parent_ptr_opt: self.parent_ptr_opt,
            node_ptr: self.node_ptr,
            flags: self.flags,
            seek: self.seek,
            uid: self.uid,
            fmaps: BTreeMap::new(),
        }))
    }

    fn set_path(&mut self, path: &str) {
        self.path = path.to_string();
    }

    fn read(&mut self, buf: &mut [u8], tx: &mut Transaction<D>) -> Result<usize> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_RDONLY {
            let atime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let count = tx.read_node(
                self.node_ptr,
                self.seek as u64,
                buf,
                atime.as_secs(),
                atime.subsec_nanos(),
            )?;
            self.seek += count as isize;
            Ok(count)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn write(&mut self, buf: &[u8], tx: &mut Transaction<D>) -> Result<usize> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_WRONLY {
            if self.flags & O_APPEND == O_APPEND {
                let node = tx.read_tree(self.node_ptr)?;
                self.seek = node.data().size() as isize;
            }
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let count = tx.write_node(
                self.node_ptr,
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

    fn seek(&mut self, offset: isize, whence: usize, tx: &mut Transaction<D>) -> Result<isize> {
        self.seek = match whence {
            SEEK_SET => max(0, offset),
            SEEK_CUR => max(0, self.seek + offset),
            SEEK_END => {
                let node = tx.read_tree(self.node_ptr)?;
                max(0, node.data().size() as isize + offset)
            }
            _ => return Err(Error::new(EINVAL)),
        };
        Ok(self.seek)
    }

    fn fmap(&mut self, map: &Map, tx: &mut Transaction<D>) -> Result<usize> {
        let accmode = self.flags & O_ACCMODE;
        if map.flags.contains(PROT_READ) && !(accmode == O_RDWR || accmode == O_RDONLY) {
            return Err(Error::new(EBADF));
        }
        if map.flags.contains(PROT_WRITE) && !(accmode == O_RDWR || accmode == O_WRONLY) {
            return Err(Error::new(EBADF));
        }
        //TODO: PROT_EXEC?

        let map = unsafe { Fmap::new(self.node_ptr, map, tx)? };
        let address = map.data.as_ptr() as usize;
        self.fmaps.insert(address, map);
        Ok(address)
    }

    fn funmap(&mut self, address: usize, tx: &mut Transaction<D>) -> Result<usize> {
        if let Some(mut fmap) = self.fmaps.remove(&address) {
            fmap.sync(tx)?;

            Ok(0)
        } else {
            Err(Error::new(EINVAL))
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

    fn path(&self) -> &str {
        &self.path
    }

    fn sync(&mut self, tx: &mut Transaction<D>) -> Result<usize> {
        for fmap in self.fmaps.values_mut() {
            fmap.sync(tx)?;
        }

        Ok(0)
    }

    fn truncate(&mut self, len: usize, tx: &mut Transaction<D>) -> Result<usize> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_WRONLY {
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            tx.truncate_node(
                self.node_ptr,
                len as u64,
                mtime.as_secs(),
                mtime.subsec_nanos(),
            )?;
            Ok(0)
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn utimens(&mut self, times: &[TimeSpec], tx: &mut Transaction<D>) -> Result<usize> {
        let mut node = tx.read_tree(self.node_ptr)?;

        if node.data().uid() == self.uid || self.uid == 0 {
            if let &[atime, mtime] = times {
                let mut node_changed = false;

                let old_mtime = node.data().mtime();
                let new_mtime = (mtime.tv_sec as u64, mtime.tv_nsec as u32);
                if old_mtime != new_mtime {
                    node.data_mut().set_mtime(new_mtime.0, new_mtime.1);
                    node_changed = true;
                }

                let old_atime = node.data().atime();
                let new_atime = (atime.tv_sec as u64, atime.tv_nsec as u32);
                if old_atime != new_atime {
                    node.data_mut().set_atime(new_atime.0, new_atime.1);
                    node_changed = true;
                }

                if node_changed {
                    tx.sync_tree(node)?;
                }
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
