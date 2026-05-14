use std::cell::RefCell;
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};

use alloc::collections::BTreeMap;
use libredox::call::MmapArgs;

use rangemap::RangeMap;
use syscall::data::{Stat, TimeSpec};
use syscall::dirent::{DirEntry, DirentBuf, DirentKind};
use syscall::error::{Error, Result, EBADF, EINVAL, EISDIR, ENOTDIR, EPERM};
use syscall::flag::{
    MapFlags, F_GETFL, F_SETFL, MODE_PERM, O_ACCMODE, O_APPEND, O_RDONLY, O_RDWR, O_WRONLY,
    PROT_READ, PROT_WRITE,
};
use syscall::{EBADFD, EIO, ENOENT, PAGE_SIZE};

use crate::{Disk, Node, Transaction, TreePtr, BLOCK_SIZE};

pub type Fmaps = BTreeMap<u32, FileMmapInfo>;

pub trait Resource<D: Disk> {
    fn parent_ptr_opt(&self) -> Option<TreePtr<Node>>;

    fn node_ptr(&self) -> TreePtr<Node>;

    fn uid(&self) -> u32;

    fn set_path(&mut self, path: &str);

    fn read(
        &mut self,
        fmaps: &mut Fmaps,
        buf: &mut [u8],
        offset: u64,
        tx: &mut Transaction<D>,
    ) -> Result<usize>;

    fn write(
        &mut self,
        fmaps: &mut Fmaps,
        buf: &[u8],
        offset: u64,
        tx: &mut Transaction<D>,
    ) -> Result<usize>;

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

    fn truncate(&mut self, fmaps: &mut Fmaps, len: u64, tx: &mut Transaction<D>) -> Result<()>;

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

    fn read(
        &mut self,
        _fmaps: &mut Fmaps,
        _buf: &mut [u8],
        _offset: u64,
        _tx: &mut Transaction<D>,
    ) -> Result<usize> {
        Err(Error::new(EISDIR))
    }

    fn write(
        &mut self,
        _fmaps: &mut Fmaps,
        _buf: &[u8],
        _offset: u64,
        _tx: &mut Transaction<D>,
    ) -> Result<usize> {
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

    fn truncate(&mut self, _fmaps: &mut Fmaps, _len: u64, _tx: &mut Transaction<D>) -> Result<()> {
        Err(Error::new(EBADF))
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
            Ok(())
        } else {
            Err(Error::new(EPERM))
        }
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
                    let child = match tx.read_tree(entry.node_ptr) {
                        Ok(r) => r,
                        Err(Error { errno: ENOENT }) => continue,
                        Err(err) => return Err(err),
                    };
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fmap {
    rc: usize,
    flags: MapFlags,
    version: u64,
}

impl Fmap {
    pub unsafe fn new<D: Disk>(
        node_ptr: TreePtr<Node>,
        flags: MapFlags,
        unaligned_size: usize,
        offset: u64,
        rc: usize,
        version: u64,
        base: *mut u8,
        tx: &mut Transaction<D>,
    ) -> Result<(Self, Option<usize>)> {
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

        Ok((
            Self { rc, flags, version },
            if count < buf.len() { Some(count) } else { None },
        ))
    }

    pub unsafe fn sync<D: Disk>(
        &self,
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
    cacheable: bool,
    parent_ptr_opt: Option<TreePtr<Node>>,
    node_ptr: TreePtr<Node>,
    flags: usize,
    uid: u32,
}

#[derive(Debug)]
pub struct FileMmapInfo {
    base: *mut u8,
    size: usize,
    // check whether the file size is known on this version
    exact_size: Option<usize>,
    pub ranges: RangeMap<u64, RefCell<Fmap>>,
    pub open_fds: usize,
    pub version: u64,
}

impl FileMmapInfo {
    pub fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            size: 0,
            exact_size: None,
            ranges: RangeMap::new(),
            open_fds: 0,
            version: 0,
        }
    }

    pub fn in_use(&self) -> bool {
        self.open_fds > 0 || self.ranges.iter().any(|(_, fmap)| fmap.borrow().rc > 0)
    }

    pub fn stale(&self) -> bool {
        // TODO: should this be any?
        // TODO: stale by duration/memory pressure
        self.ranges
            .iter()
            .all(|(_, fmap)| fmap.borrow().version != self.version)
    }

    pub fn get_cache_readable_count(&self, offset: u64, requested_end: u64) -> Option<usize> {
        let mut next_offset = offset;
        let mut eof = false;
        for (range, fmap) in self.ranges.overlapping(&(offset..requested_end)) {
            let fmap = fmap.borrow();
            if range.start > next_offset || fmap.version != self.version {
                break;
            }
            next_offset = range.end;
        }
        if let Some(end) = self.exact_size.as_ref() {
            next_offset = core::cmp::min(next_offset, *end as u64);
            eof = true;
        }

        if next_offset > offset || (eof && offset == next_offset) {
            usize::try_from(core::cmp::min(next_offset - offset, requested_end - offset)).ok()
        } else {
            None
        }
    }

    pub unsafe fn ensure_capacity(&mut self, required_size: usize) -> Result<usize> {
        let aligned_size = required_size.next_multiple_of(PAGE_SIZE);
        if aligned_size <= self.size {
            return Ok(aligned_size);
        }

        self.base = if self.base.is_null() {
            libredox::call::mmap(MmapArgs {
                length: aligned_size,
                prot: libredox::flag::PROT_READ | libredox::flag::PROT_WRITE,
                flags: libredox::flag::MAP_PRIVATE,
                offset: 0,
                fd: !0,
                addr: core::ptr::null_mut(),
            })? as *mut u8
        } else {
            syscall::syscall5(
                syscall::SYS_MREMAP,
                self.base as usize,
                self.size,
                0,
                aligned_size,
                (PROT_READ | PROT_WRITE).bits(),
            )? as *mut u8
        };
        self.size = aligned_size;
        Ok(aligned_size)
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
        let cacheable = Self::is_cacheable(&path);
        FileResource {
            path,
            cacheable,
            parent_ptr_opt,
            node_ptr,
            flags,
            uid,
        }
    }
    pub fn is_cacheable(path: &str) -> bool {
        if path.len() == 0 {
            false
        } else {
            match path.as_bytes()[0] {
                b'u' => {
                    path.starts_with("usr/lib/")
                        || path.starts_with("usr/bin/")
                        || path.starts_with("usr/include/")
                }
                b'b' => path.starts_with("bin/"),
                b'l' => path.starts_with("lib/"),
                b'e' => path.starts_with("etc/"),
                _ => false,
            }
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

    fn read(
        &mut self,
        fmaps: &mut Fmaps,
        buf: &mut [u8],
        offset: u64,
        tx: &mut Transaction<D>,
    ) -> Result<usize> {
        if self.flags & O_ACCMODE != O_RDWR && self.flags & O_ACCMODE != O_RDONLY {
            return Err(Error::new(EBADF));
        }
        if let Some(fmap_info) = fmaps.get_mut(&self.node_ptr.id()) {
            if !fmap_info.base.is_null() {
                let requested_end = offset + buf.len() as u64;
                if let Some(count) = fmap_info.get_cache_readable_count(offset, requested_end) {
                    // println!(
                    //     "MMAP READ {} {:x}-{:x} ({:x})",
                    //     self.path,
                    //     offset,
                    //     offset + buf.len() as u64,
                    //     offset + (count as u64)
                    // );
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            fmap_info.base.add(offset as usize),
                            buf.as_mut_ptr(),
                            count,
                        );
                    }
                    return Ok(count);
                }
            }
        }

        let atime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let len = tx.read_node(
            self.node_ptr,
            offset,
            buf,
            atime.as_secs(),
            atime.subsec_nanos(),
        )?;

        if self.cacheable {
            // TODO: out of bound offset can trigger oom, rearrange fmap to avoid such thing
            // println!(
            //     "MMAP WRITE {} {:x}-{:x}",
            //     self.path,
            //     offset,
            //     offset + len as u64
            // );
            self.fmap(fmaps, MapFlags::PROT_READ, len, offset, tx)?;
            self.funmap(fmaps, offset, len, tx)?;
        }

        // println!(
        //     "read disk {} {:x}-{:x} ({:x})",
        //     self.path,
        //     offset,
        //     offset + buf.len() as u64,
        //     offset + len as u64,
        // );

        Ok(len)
    }

    fn write(
        &mut self,
        fmaps: &mut Fmaps,
        buf: &[u8],
        offset: u64,
        tx: &mut Transaction<D>,
    ) -> Result<usize> {
        if self.flags & O_ACCMODE != O_RDWR && self.flags & O_ACCMODE != O_WRONLY {
            return Err(Error::new(EBADF));
        }
        let effective_offset = if self.flags & O_APPEND == O_APPEND {
            let node = tx.read_tree(self.node_ptr)?;
            node.data().size()
        } else {
            offset
        };
        if let Some(fmap_info) = fmaps.get_mut(&self.node_ptr.id()) {
            fmap_info.version += 1;
        }
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

        let aligned_end = unsafe {
            fmap_info.ensure_capacity(
                (offset as usize)
                    .checked_add(unaligned_size)
                    .ok_or(Error::new(EIO))?,
            )?
        } as u64;
        let aligned_start = offset / (PAGE_SIZE as u64) * (PAGE_SIZE as u64);
        let range_to_map = aligned_start..aligned_end;
        for (range, overlap) in fmap_info.ranges.overlapping(&range_to_map) {
            let mut map = overlap.borrow_mut();
            if map.version != fmap_info.version {
                let (fmap, count) = unsafe {
                    // println!("update cache {:x}-{:x}", range.start, range.end);
                    Fmap::new(
                        self.node_ptr,
                        flags,
                        (range.end - range.start) as usize,
                        range.start,
                        map.rc,
                        fmap_info.version,
                        fmap_info.base,
                        tx,
                    )?
                };
                *map = fmap;
                if let Some(count) = count {
                    if let Some(old_count) = fmap_info.exact_size.replace(count) {
                        assert_eq!(count, old_count);
                    }
                }
            }
            map.rc += 1;
        }
        for gap in fmap_info.ranges.gaps(&range_to_map).collect::<Vec<_>>() {
            let (fmap, count) = unsafe {
                Fmap::new(
                    self.node_ptr,
                    flags,
                    (gap.end - gap.start) as usize,
                    gap.start,
                    1,
                    fmap_info.version,
                    fmap_info.base,
                    tx,
                )?
            };
            // println!("write cache {:x}-{:x}", gap.start, gap.end);
            fmap_info.ranges.insert(gap.clone(), RefCell::new(fmap));
            if let Some(count) = count {
                // println!("write cache cap {:x}", gap.start + count as u64);
                if let Some(old_count) = fmap_info.exact_size.replace(gap.start as usize + count) {
                    assert_eq!(count, old_count);
                }
            }
        }

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

        let aligned_start = offset / (PAGE_SIZE as u64) * (PAGE_SIZE as u64);
        let aligned_end = (offset + size as u64).next_multiple_of(PAGE_SIZE as u64);
        let range_to_map = aligned_start..aligned_end;
        let affected_fmaps = fmap_info.ranges.overlapping(range_to_map);

        for (range, fmap) in affected_fmaps {
            let mut map = fmap.borrow_mut();
            map.rc = map.rc.checked_sub(1).unwrap();
            unsafe {
                map.sync(
                    self.node_ptr,
                    fmap_info.base,
                    range.start,
                    (range.end - range.start) as usize,
                    tx,
                )?;
            }
        }
        //dbg!(&self.fmaps);

        // Allow release of node if not in use anymore
        if !fmap_info.in_use() {
            // Notify filesystem of close
            tx.on_close_node(self.node_ptr)?;

            // if this fmap version is outdated it's no use
            if fmap_info.stale() {
                let fmap = fmaps
                    .remove(&self.node_ptr.id())
                    .expect("fmap_info must exist");

                if let Err(e) = unsafe { libredox::call::munmap(fmap.base as *mut _, fmap.size) } {
                    log::error!("Munmap error {e}");
                }
            }
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
            for (range, fmap) in fmap_info.ranges.iter() {
                unsafe {
                    fmap.borrow().sync(
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

    fn truncate(&mut self, fmaps: &mut Fmaps, len: u64, tx: &mut Transaction<D>) -> Result<()> {
        if self.flags & O_ACCMODE == O_RDWR || self.flags & O_ACCMODE == O_WRONLY {
            let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            tx.truncate_node(self.node_ptr, len, mtime.as_secs(), mtime.subsec_nanos())?;
            if let Some(fmap_info) = fmaps.get_mut(&self.node_ptr.id()) {
                fmap_info.exact_size = usize::try_from(len).ok();
            }
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
