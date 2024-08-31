use core::hash::Hash;
use core::num::NonZeroUsize;
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};

use alloc::collections::BTreeMap;
use libredox::call::MmapArgs;
use range_tree::RangeTree;

use syscall::data::{Stat, TimeSpec};
use syscall::error::{Error, Result, EBADF, EINVAL, EISDIR, EPERM};
use syscall::flag::{
    MapFlags, F_GETFL, F_SETFL, MODE_PERM, O_ACCMODE, O_APPEND, O_RDONLY, O_RDWR, O_WRONLY,
    PROT_READ, PROT_WRITE
};
use syscall::{EBADFD, PAGE_SIZE};

use crate::{Disk, Node, Transaction, TreePtr};

#[derive(Debug)]
pub struct Fmap {
    pub(crate) rc: usize,
    pub(crate) flags: MapFlags,
    pub(crate) last_page_tail: u16,
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
}

pub struct InodeInfo {
    pub(crate) parent_ptr_opt: Option<TreePtr<Node>>,
    pub(crate) kind: InodeKind,

    // Counts references to this inode. If both this and nlink approach zero, the inode will (TODO)
    // be deallocated when closed. Inodes are kept alive if `mmaps` is nonempty, however.
    pub(crate) open_handles: usize,
}
pub struct InodeKey(pub TreePtr<Node>);

impl PartialEq for InodeKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.id() == other.0.id()
    }
}
impl Eq for InodeKey {}
impl Hash for InodeKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write_u32(self.0.id())
    }
}

pub enum InodeKind {
    Dir,
    File {
        mmaps: FileMmapInfo,
    },
}

#[derive(Debug)]
pub struct FileMmapInfo {
    pub(crate) base: *mut u8,
    pub(crate) size: usize,
    pub(crate) ranges: RangeTree<Fmap>,
}
impl FileMmapInfo {
    unsafe fn sync_single<D: Disk>(base: *mut u8, inode: TreePtr<Node>, offset: u64, size: usize, tx: &mut Transaction<D>) -> Result<()> {
        let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        tx.write_node(
            inode,
            offset,
            unsafe { core::slice::from_raw_parts(base.add(offset as usize), size) },
            mtime.as_secs(),
            mtime.subsec_nanos(),
        )?;
        Ok(())
    }
    // TODO: Pass a range to intersect with, when the msync syscall is actually implemented
    pub unsafe fn msync<D: Disk>(&mut self, inode: TreePtr<Node>, tx: &mut Transaction<D>) -> Result<()> {
        for (range, mmap_info) in self.ranges.iter().filter(|(_, mm)| mm.flags.contains(PROT_WRITE)) {
            Self::sync_single(self.base, inode, range.start, usize::try_from(range.end - range.start).unwrap(), tx)?;
        }
        Ok(())
    }
    pub unsafe fn munmap<D: Disk>(&mut self, inode: TreePtr<Node>, offset: u64, size: usize, tx: &mut Transaction<D>) -> Result<()> {
        let mtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        #[allow(unused_mut)]
        let mut affected_fmaps = self.ranges.remove(offset..offset + size as u64);

        for (range, mut fmap) in affected_fmaps {
            fmap.rc = fmap.rc.checked_sub(1).unwrap();

            //log::info!("SYNCING {}..{}", range.start, range.end);
            unsafe {
                Self::sync_single(self.base, inode, range.start, usize::try_from(range.end - range.start).unwrap(), tx)?;
            }

            if fmap.rc > 0 {
                let _ = self
                    .ranges
                    .insert(range.start, range.end - range.start, fmap);
            }
        }
        Ok(())
    }
}
impl Default for FileMmapInfo {
    fn default() -> Self {
        Self {
            base: core::ptr::null_mut(),
            size: 0,
            ranges: RangeTree::new(),
        }
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
