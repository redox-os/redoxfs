use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};

use alloc::collections::BTreeMap;
use libredox::call::MmapArgs;
use range_tree::RangeTree;

use syscall::data::{Stat, TimeSpec};
use syscall::dirent::{DirEntry, DirentBuf, DirentKind};
use syscall::error::{Error, Result, EBADF, EINVAL, EISDIR, ENOTDIR, EPERM};
use syscall::flag::{
    MapFlags, F_GETFL, F_SETFL, MODE_PERM, O_ACCMODE, O_APPEND, O_NOATIME, O_RDONLY, O_RDWR,
    O_WRONLY, PROT_READ, PROT_WRITE,
};
use syscall::{EBADFD, PAGE_SIZE};

use crate::{Disk, Node, Transaction, TreePtr, BLOCK_SIZE};

pub type Fmaps = BTreeMap<u32, FileMmapInfo>;

pub trait Resource<D: Disk> {
    fn parent_ptr_opt(&self) -> Option<TreePtr<Node>>;

    fn node_ptr(&self) -> TreePtr<Node>;

    fn uid(&self) -> u32;

    fn set_path(&mut self, path: &str);

    fn read(&mut self, buf: &mut [u8], offset: u64, tx: &mut Transaction<D>) -> Result<usize>;

    fn write(&mut self, buf: &[u8], offset: u64, tx: &mut Transaction<D>) -> Result<usize>;

    fn fsize(&mut self, tx: &mut Transaction<D>) -> Result<u64>;

    fn fmap(
        &mut self,
        fmaps: &mut Fmaps,
        flags: MapFlags,
        size: usize,
        offset: u64,
        tx: &mut Transaction<D>,
    ) -> Result<usize>;

    fn funmap(
        &mut self,
        fmaps: &mut Fmaps,
        offset: u64,
        size: usize,
        tx: &mut Transaction<D>,
    ) -> Result<()>;

    fn fchmod(&mut self, mode: u16, tx: &mut Transaction<D>) -> Result<()> {
        let mut node = tx.read_tree(self.node_ptr())?;

        if node.data().uid() == self.uid() || self.uid() == 0 {
            let old_mode = node.data().mode();
            let new_mode = (old_mode & !MODE_PERM) | (mode & MODE_PERM);
            if old_mode != new_mode {
                node.data_mut().set_mode(new_mode);
                tx.sync_tree(node)?;
            }

            Ok(())
        } else {
            Err(Error::new(EPERM))
        }
    }

    fn fchown(&mut self, uid: u32, gid: u32, tx: &mut Transaction<D>) -> Result<()> {
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

            Ok(())
        } else {
            Err(Error::new(EPERM))
        }
    }

    fn fcntl(&mut self, cmd: usize, arg: usize) -> Result<usize>;

    fn path(&self) -> &str;

    fn stat(&self, stat: &mut Stat, tx: &mut Transaction<D>) -> Result<()> {
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
            st_blksize: 512,
            // Blocks is in 512 byte blocks, not in our block size
            st_blocks: node.data().blocks() * (BLOCK_SIZE / 512),
            st_mtime: mtime.0,
            st_mtime_nsec: mtime.1,
            st_atime: atime.0,
            st_atime_nsec: atime.1,
            st_ctime: ctime.0,
            st_ctime_nsec: ctime.1,
        };

        Ok(())
    }

    fn sync(&mut self, fmaps: &mut Fmaps, tx: &mut Transaction<D>) -> Result<()>;

    fn truncate(&mut self, len: u64, tx: &mut Transaction<D>) -> Result<()>;

    fn utimens(&mut self, times: &[TimeSpec], tx: &mut Transaction<D>) -> Result<()>;

    fn getdents<'buf>(
        &mut self,
        buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
        tx: &mut Transaction<D>,
    ) -> Result<DirentBuf<&'buf mut [u8]>>;
}

pub struct Entry {
    pub node_ptr: TreePtr<Node>,
    pub name: String,
}

pub struct DirResource {
    path: String,
    parent_ptr_opt: Option<TreePtr<Node>>,
    node_ptr: TreePtr<Node>,
    data: Option<Vec<Entry>>,
    uid: u32,
}

impl DirResource {
    pub fn new(
        path: String,
        parent_ptr_opt: Option<TreePtr<Node>>,
        node_ptr: TreePtr<Node>,
        data: Option<Vec<Entry>>,
        uid: u32,
    ) -> DirResource {
        DirResource {
            path,
            parent_ptr_opt,
            node_ptr,
            data,
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

    fn set_path(&mut self, path: &str) {
        self.path = path.to_string();
    }

    fn read(&mut self, _buf: &mut [u8], _offset: u64, _tx: &mut Transaction<D>) -> Result<usize> {
        Err(Error::new(EISDIR))
    }

    fn write(&mut self, _buf: &[u8], _offset: u64, _tx: &mut Transaction<D>) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn fsize(&mut self, _tx: &mut Transaction<D>) -> Result<u64> {
        Ok(self.data.as_ref().ok_or(Error::new(EBADF))?.len() as u64)
    }

    fn fmap(
        &mut self,
        _fmaps: &mut Fmaps,
        _flags: MapFlags,
        _size: usize,
        _offset: u64,
        _tx: &mut Transaction<D>,
    ) -> Result<usize> {
        Err(Error::new(EBADF))
    }
    fn funmap(
        &mut self,
        _fmaps: &mut Fmaps,
        _offset: u64,
        _size: usize,
        _tx: &mut Transaction<D>,
    ) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn fcntl(&mut self, _cmd: usize, _arg: usize) -> Result<usize> {
        Err(Error::new(EBADF))
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn sync(&mut self, _fmaps: &mut Fmaps, _tx: &mut Transaction<D>) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn truncate(&mut self, _len: u64, _tx: &mut Transaction<D>) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn utimens(&mut self, _times: &[TimeSpec], _tx: &mut Transaction<D>) -> Result<()> {
        Err(Error::new(EBADF))
    }

    fn getdents<'buf>(
        &mut self,
        mut buf: DirentBuf<&'buf mut [u8]>,
        opaque_offset: u64,
        tx: &mut Transaction<D>,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        match &self.data {
            Some(data) => {
                let opaque_offset = opaque_offset as usize;
                for (idx, entry) in data.iter().enumerate().skip(opaque_offset) {
                    let child = tx.read_tree(entry.node_ptr)?;
                    let result = buf.entry(DirEntry {
                        inode: child.id() as u64,
                        next_opaque_id: idx as u64 + 1,
                        name: &entry.name,
                        kind: match child.data().mode() & Node::MODE_TYPE {
                            Node::MODE_DIR => DirentKind::Directory,
                            Node::MODE_FILE => DirentKind::Regular,
                            Node::MODE_SYMLINK => DirentKind::Symlink,
                            //TODO: more types?
                            _ => DirentKind::Unspecified,
                        },
                    });
                    if let Err(err) = result {
                        if err.errno == EINVAL && idx > opaque_offset {
                            // POSIX allows partial result of getdents
                            break;
                        } else {
                            return Err(err);
                        }
                    }
                }
                Ok(buf)
            }
            None => Err(Error::new(EBADF)),
        }
    }
}

#[derive(Debug)]
pub struct Fmap {
    rc: usize,
    flags: MapFlags,
    last_page_tail: u16,
}

impl Fmap {
    pub unsafe fn new<D: Disk>(
        node_ptr: TreePtr<Node>,
        flags: MapFlags,
        unaligned_size: usize,
        offset: u64,
        base: *mut u8,
        tx: &mut Transaction<D>,
    ) -> Result<Self> {
        // Memory provided to fmap must be page aligned and sized
        let aligned_size = unaligned_size.next_multiple_of(syscall::PAGE_SIZE);

        let address = base.add(offset as usize);
        //println!("ADDR {:p} {:p}", base, address);

        // Read buffer from disk
        let atime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let buf = slice::from_raw_parts_mut(address, unaligned_size);

        let count = match tx.read_node(node_ptr, offset, buf, atime.as_secs(), atime.subsec_nanos())
        {
            Ok(ok) => ok,
            Err(err) => {
                let _ = libredox::call::munmap(address.cast(), aligned_size);
                return Err(err);
            }
        };

        // Make sure remaining data is zeroed
        buf[count..].fill(0_u8);

        Ok(Self {
            rc: 1,
            flags,
            last_page_tail: (unaligned_size % PAGE_SIZE) as u16,
        })
    }

    pub unsafe fn sync<D: Disk>(
        &mut self,
        node_ptr: TreePtr<Node>,
        base: *mut u8,
        offset: u64,
        size: usize,
        tx: &mut Transaction<D>,
    ) -> Result<()> {
        if self.flags & PROT_WRITE == PROT_WRITE {
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            tx.write_node(
                node_ptr,
                offset,
                unsafe { core::slice::from_raw_parts(base.add(offset as usize), size) },
                mtime.as_secs(),
                mtime.subsec_nanos(),
            )?;
        }
        Ok(())
    }
}

pub struct FileResource {
    path: String,
    parent_ptr_opt: Option<TreePtr<Node>>,
    node_ptr: TreePtr<Node>,
    flags: usize,
    uid: u32,
}

#[derive(Debug)]
pub struct FileMmapInfo {
    base: *mut u8,
    size: usize,
    pub ranges: RangeTree<Fmap>,
    pub open_fds: usize,
}

impl FileMmapInfo {
    pub fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            size: 0,
            ranges: RangeTree::new(),
            open_fds: 0,
        }
    }

    pub fn in_use(&self) -> bool {
        self.open_fds > 0 || !self.ranges.is_empty()
    }
}

impl Drop for FileMmapInfo {
    fn drop(&mut self) {
        if self.in_use() {
            log::error!("FileMmapInfo dropped while in use");
        }
    }
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
            uid,
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

    fn set_path(&mut self, path: &str) {
        self.path = path.to_string();
    }

    fn read(&mut self, buf: &mut [u8], offset: u64, tx: &mut Transaction<D>) -> Result<usize> {
        if self.flags & O_ACCMODE != O_RDWR && self.flags & O_ACCMODE != O_RDONLY {
            return Err(Error::new(EBADF));
        }
        if self.flags & O_NOATIME != O_NOATIME {
            let atime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        }
        tx.read_node(
            self.node_ptr,
            offset,
            buf,
            atime.as_secs(),
            atime.subsec_nanos(),
        )
    }

    fn write(&mut self, buf: &[u8], offset: u64, tx: &mut Transaction<D>) -> Result<usize> {
        if self.flags & O_ACCMODE != O_RDWR && self.flags & O_ACCMODE != O_WRONLY {
            return Err(Error::new(EBADF));
        }
        let effective_offset = if self.flags & O_APPEND == O_APPEND {
            let node = tx.read_tree(self.node_ptr)?;
            node.data().size()
        } else {
            offset
        };
        let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        tx.write_node(
            self.node_ptr,
            effective_offset,
            buf,
            mtime.as_secs(),
            mtime.subsec_nanos(),
        )
    }

    fn fsize(&mut self, tx: &mut Transaction<D>) -> Result<u64> {
        let node = tx.read_tree(self.node_ptr)?;
        Ok(node.data().size())
    }

    fn fmap(
        &mut self,
        fmaps: &mut Fmaps,
        flags: MapFlags,
        unaligned_size: usize,
        offset: u64,
        tx: &mut Transaction<D>,
    ) -> Result<usize> {
        //dbg!(&self.fmaps);
        let accmode = self.flags & O_ACCMODE;
        if flags.contains(PROT_READ) && !(accmode == O_RDWR || accmode == O_RDONLY) {
            return Err(Error::new(EBADF));
        }
        if flags.contains(PROT_WRITE) && !(accmode == O_RDWR || accmode == O_WRONLY) {
            return Err(Error::new(EBADF));
        }

        let aligned_size = unaligned_size.next_multiple_of(PAGE_SIZE);

        // TODO: PROT_EXEC? It is however unenforcable without restricting anonymous mmap, since a
        // program can always map anonymous RW-, read from a file, then remap as R-E. But it might
        // be usable as a hint, prohibiting direct executable mmaps at least.

        // TODO: Pass entry directory to Resource trait functions, since the node_ptr can be
        // obtained by the caller.
        let fmap_info = fmaps
            .get_mut(&self.node_ptr.id())
            .ok_or(Error::new(EBADFD))?;

        if !fmap_info.in_use() {
            // Notify filesystem of open
            tx.on_open_node(self.node_ptr)?;
        }

        let new_size = (offset as usize + aligned_size).next_multiple_of(PAGE_SIZE);
        if new_size > fmap_info.size {
            fmap_info.base = if fmap_info.base.is_null() {
                unsafe {
                    libredox::call::mmap(MmapArgs {
                        length: new_size,
                        // PRIVATE/SHARED doesn't matter once the pages are passed in the fmap
                        // handler.
                        prot: libredox::flag::PROT_READ | libredox::flag::PROT_WRITE,
                        flags: libredox::flag::MAP_PRIVATE,

                        offset: 0,
                        fd: !0,
                        addr: core::ptr::null_mut(),
                    })? as *mut u8
                }
            } else {
                unsafe {
                    syscall::syscall5(
                        syscall::SYS_MREMAP,
                        fmap_info.base as usize,
                        fmap_info.size,
                        0,
                        new_size,
                        syscall::MremapFlags::empty().bits() | (PROT_READ | PROT_WRITE).bits(),
                    )? as *mut u8
                }
            };
            fmap_info.size = new_size;
        }

        let affected_fmaps = fmap_info
            .ranges
            .remove_and_unused(offset..offset + aligned_size as u64);

        for (range, v_opt) in affected_fmaps {
            //dbg!(&range);
            if let Some(mut fmap) = v_opt {
                fmap.rc += 1;
                fmap.flags |= flags;
                //FIXME: Use result?
                let _ = fmap_info
                    .ranges
                    .insert(range.start, range.end - range.start, fmap);
            } else {
                let map = unsafe {
                    Fmap::new(
                        self.node_ptr,
                        flags,
                        unaligned_size,
                        offset,
                        fmap_info.base,
                        tx,
                    )?
                };
                //FIXME: Use result?
                let _ = fmap_info.ranges.insert(offset, aligned_size as u64, map);
            }
        }
        //dbg!(&self.fmaps);

        Ok(fmap_info.base as usize + offset as usize)
    }

    fn funmap(
        &mut self,
        fmaps: &mut Fmaps,
        offset: u64,
        size: usize,
        tx: &mut Transaction<D>,
    ) -> Result<()> {
        let fmap_info = fmaps
            .get_mut(&self.node_ptr.id())
            .ok_or(Error::new(EBADFD))?;

        //dbg!(&self.fmaps);
        //dbg!(self.fmaps.conflicts(offset..offset + size as u64).collect::<Vec<_>>());
        #[allow(unused_mut)]
        let mut affected_fmaps = fmap_info.ranges.remove(offset..offset + size as u64);

        for (range, mut fmap) in affected_fmaps {
            fmap.rc = fmap.rc.checked_sub(1).unwrap();

            //log::info!("SYNCING {}..{}", range.start, range.end);
            unsafe {
                fmap.sync(
                    self.node_ptr,
                    fmap_info.base,
                    range.start,
                    (range.end - range.start) as usize,
                    tx,
                )?;
            }

            if fmap.rc > 0 {
                //FIXME: Use result?
                let _ = fmap_info
                    .ranges
                    .insert(range.start, range.end - range.start, fmap);
            }
        }
        //dbg!(&self.fmaps);

        // Allow release of node if not in use anymore
        if !fmap_info.in_use() {
            // Notify filesystem of close
            tx.on_close_node(self.node_ptr)?;

            /*TODO: leaks memory, but why?
            // Remove from fmaps list
            fmaps.remove(&self.node_ptr.id());
            */
        }

        Ok(())
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

    fn sync(&mut self, fmaps: &mut Fmaps, tx: &mut Transaction<D>) -> Result<()> {
        if let Some(fmap_info) = fmaps.get_mut(&self.node_ptr.id()) {
            for (range, fmap) in fmap_info.ranges.iter_mut() {
                unsafe {
                    fmap.sync(
                        self.node_ptr,
                        fmap_info.base,
                        range.start,
                        (range.end - range.start) as usize,
                        tx,
                    )?;
                }
            }
        }

        Ok(())
    }

    fn truncate(&mut self, len: u64, tx: &mut Transaction<D>) -> Result<()> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_WRONLY {
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            tx.truncate_node(self.node_ptr, len, mtime.as_secs(), mtime.subsec_nanos())?;
            Ok(())
        } else {
            Err(Error::new(EBADF))
        }
    }

    fn utimens(&mut self, times: &[TimeSpec], tx: &mut Transaction<D>) -> Result<()> {
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

                if self.flags & O_NOATIME != O_NOATIME {
                    let old_atime = node.data().atime();
                    let new_atime = (atime.tv_sec as u64, atime.tv_nsec as u32);
                    if old_atime != new_atime {
                        node.data_mut().set_atime(new_atime.0, new_atime.1);
                        node_changed = true;
                    }
                }

                if node_changed {
                    tx.sync_tree(node)?;
                }
            }
            Ok(())
        } else {
            Err(Error::new(EPERM))
        }
    }

    fn getdents<'buf>(
        &mut self,
        _buf: DirentBuf<&'buf mut [u8]>,
        _opaque_offset: u64,
        _tx: &mut Transaction<D>,
    ) -> Result<DirentBuf<&'buf mut [u8]>> {
        Err(Error::new(ENOTDIR))
    }
}

impl Drop for FileResource {
    fn drop(&mut self) {
        /*
        if !self.fmaps.is_empty() {
            eprintln!(
                "redoxfs: file {} still has {} fmaps!",
                self.path,
                self.fmaps.len()
            );
        }
        */
    }
}

impl range_tree::Value for Fmap {
    type K = u64;

    fn try_merge_forward(self, other: &Self) -> core::result::Result<Self, Self> {
        if self.rc == other.rc && self.flags == other.flags && self.last_page_tail == 0 {
            Ok(self)
        } else {
            Err(self)
        }
    }
    fn try_merge_backwards(self, other: &Self) -> core::result::Result<Self, Self> {
        if self.rc == other.rc && self.flags == other.flags && other.last_page_tail == 0 {
            Ok(self)
        } else {
            Err(self)
        }
    }
    #[allow(unused_variables)]
    fn split(
        self,
        prev_range: Option<core::ops::Range<Self::K>>,
        range: core::ops::Range<Self::K>,
        next_range: Option<core::ops::Range<Self::K>>,
    ) -> (Option<Self>, Self, Option<Self>) {
        (
            prev_range.map(|_range| Fmap {
                rc: self.rc,
                flags: self.flags,
                last_page_tail: 0,
            }),
            Fmap {
                rc: self.rc,
                flags: self.flags,
                last_page_tail: if next_range.is_none() {
                    self.last_page_tail
                } else {
                    0
                },
            },
            next_range.map(|_range| Fmap {
                rc: self.rc,
                flags: self.flags,
                last_page_tail: self.last_page_tail,
            }),
        )
    }
}
