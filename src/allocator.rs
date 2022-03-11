use alloc::vec::Vec;
use core::{fmt, mem, ops, slice};
use redox_simple_endian::*;

use crate::BlockPtr;

pub const ALLOC_LIST_ENTRIES: usize = 255;

#[derive(Clone, Default)]
pub struct Allocator {
    levels: Vec<Vec<u64>>,
}

impl Allocator {
    pub fn levels(&self) -> &Vec<Vec<u64>> {
        &self.levels
    }

    pub fn free(&self) -> u64 {
        let mut free = 0;
        for level in 0..self.levels.len() {
            let level_size = 1 << level;
            free += self.levels[level].len() as u64 * level_size;
        }
        free
    }

    pub fn allocate(&mut self) -> Option<u64> {
        // First, find the lowest level with a free block
        let mut addr_opt = None;
        let mut level = 0;
        while level < self.levels.len() {
            if !self.levels[level].is_empty() {
                addr_opt = self.levels[level].pop();
                break;
            }
            level += 1;
        }

        // Next, if a free block was found, split it up until you have a usable level 0 block
        let addr = addr_opt?;
        while level > 0 {
            level -= 1;
            let level_size = 1 << level;
            self.levels[level].push(addr + level_size);
        }

        Some(addr)
    }

    pub fn allocate_exact(&mut self, exact_addr: u64) -> Option<u64> {
        let mut addr_opt = None;

        // Go from the highest to the lowest level
        for level in (0..self.levels.len()).rev() {
            let level_size = 1 << level;

            // Split higher block if found
            if let Some(addr) = addr_opt.take() {
                self.levels[level].push(addr);
                self.levels[level].push(addr + level_size);
            }

            // Look for matching block and remove it
            for i in 0..self.levels[level].len() {
                let start = self.levels[level][i];
                if start <= exact_addr {
                    let end = start + level_size;
                    if end > exact_addr {
                        self.levels[level].remove(i);
                        addr_opt = Some(start);
                        break;
                    }
                }
            }
        }

        addr_opt
    }

    pub fn deallocate(&mut self, mut addr: u64) {
        // See if block matches with a sibling - if so, join them into a larger block, and populate
        // this all the way to the top level
        let mut level = 0;
        loop {
            while level >= self.levels.len() {
                self.levels.push(Vec::new());
            }

            let level_size = 1 << level;
            let next_size = level_size << 1;

            let mut found = false;
            let mut i = 0;
            while i < self.levels[level].len() {
                let level_addr = self.levels[level][i];
                if addr % next_size == 0 && addr + level_size == level_addr {
                    self.levels[level].remove(i);
                    found = true;
                    break;
                } else if level_addr % next_size == 0 && level_addr + level_size == addr {
                    self.levels[level].remove(i);
                    addr = level_addr;
                    found = true;
                    break;
                }
                i += 1;
            }

            if !found {
                self.levels[level].push(addr);
                return;
            }

            level += 1;
        }
    }
}

#[repr(packed)]
pub struct AllocEntry {
    addr: u64le,
    count: i64le,
}

impl AllocEntry {
    pub fn new(addr: u64, count: i64) -> Self {
        Self {
            addr: addr.into(),
            count: count.into(),
        }
    }

    pub fn addr(&self) -> u64 {
        { self.addr }.to_native()
    }

    pub fn count(&self) -> i64 {
        { self.count }.to_native()
    }

    pub fn is_null(&self) -> bool {
        self.count() == 0
    }
}

impl Clone for AllocEntry {
    fn clone(&self) -> Self {
        Self {
            addr: self.addr,
            count: self.count,
        }
    }
}

impl Copy for AllocEntry {}

impl Default for AllocEntry {
    fn default() -> Self {
        Self {
            addr: 0.into(),
            count: 0.into(),
        }
    }
}

impl fmt::Debug for AllocEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let addr = self.addr();
        let count = self.count();
        f.debug_struct("AllocEntry")
            .field("addr", &addr)
            .field("count", &count)
            .finish()
    }
}

/// Alloc log node
#[repr(packed)]
pub struct AllocList {
    pub prev: BlockPtr<AllocList>,
    pub entries: [AllocEntry; ALLOC_LIST_ENTRIES],
}

impl Default for AllocList {
    fn default() -> Self {
        Self {
            prev: BlockPtr::default(),
            entries: [AllocEntry::default(); ALLOC_LIST_ENTRIES],
        }
    }
}

impl fmt::Debug for AllocList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let prev = self.prev;
        let entries: Vec<&AllocEntry> = self
            .entries
            .iter()
            .filter(|entry| entry.count() > 0)
            .collect();
        f.debug_struct("AllocList")
            .field("prev", &prev)
            .field("entries", &entries)
            .finish()
    }
}

impl ops::Deref for AllocList {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const AllocList as *const u8,
                mem::size_of::<AllocList>(),
            ) as &[u8]
        }
    }
}

impl ops::DerefMut for AllocList {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self as *mut AllocList as *mut u8,
                mem::size_of::<AllocList>(),
            ) as &mut [u8]
        }
    }
}

#[test]
fn alloc_node_size_test() {
    assert_eq!(mem::size_of::<AllocList>(), crate::BLOCK_SIZE as usize);
}

#[test]
fn allocator_test() {
    let mut alloc = Allocator::default();

    assert_eq!(alloc.allocate(), None);

    alloc.deallocate(1);
    assert_eq!(alloc.allocate(), Some(1));
    assert_eq!(alloc.allocate(), None);

    for addr in 1023..2048 {
        alloc.deallocate(addr);
    }

    assert_eq!(alloc.levels.len(), 11);
    for level in 0..alloc.levels.len() {
        if level == 0 {
            assert_eq!(alloc.levels[level], [1023]);
        } else if level == 10 {
            assert_eq!(alloc.levels[level], [1024]);
        } else {
            assert_eq!(alloc.levels[level], []);
        }
    }

    for addr in 1023..2048 {
        assert_eq!(alloc.allocate(), Some(addr));
    }
    assert_eq!(alloc.allocate(), None);

    assert_eq!(alloc.levels.len(), 11);
    for level in 0..alloc.levels.len() {
        assert_eq!(alloc.levels[level], []);
    }
}
