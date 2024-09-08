use alloc::vec::Vec;
use core::{fmt, mem, ops, slice};
use endian_num::Le;

use crate::{BlockAddr, BlockLevel, BlockPtr, BlockTrait, BLOCK_SIZE};

pub const ALLOC_LIST_ENTRIES: usize =
    (BLOCK_SIZE as usize - mem::size_of::<BlockPtr<AllocList>>()) / mem::size_of::<AllocEntry>();

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

    pub fn allocate(&mut self, block_level: BlockLevel) -> Option<BlockAddr> {
        // First, find the lowest level with a free block
        let mut index_opt = None;
        let mut level = block_level.0;
        while level < self.levels.len() {
            if !self.levels[level].is_empty() {
                index_opt = self.levels[level].pop();
                break;
            }
            level += 1;
        }

        // Next, if a free block was found, split it up until you have a usable block of the right level
        let index = index_opt?;
        while level > block_level.0 {
            level -= 1;
            let level_size = 1 << level;
            self.levels[level].push(index + level_size);
        }

        Some(unsafe { BlockAddr::new(index, block_level) })
    }

    pub fn allocate_exact(&mut self, exact_addr: BlockAddr) -> Option<BlockAddr> {
        // This function only supports level 0 right now
        assert_eq!(exact_addr.level().0, 0);
        let exact_index = exact_addr.index();

        let mut index_opt = None;

        // Go from the highest to the lowest level
        for level in (0..self.levels.len()).rev() {
            let level_size = 1 << level;

            // Split higher block if found
            if let Some(index) = index_opt.take() {
                self.levels[level].push(index);
                self.levels[level].push(index + level_size);
            }

            // Look for matching block and remove it
            for i in 0..self.levels[level].len() {
                let start = self.levels[level][i];
                if start <= exact_index {
                    let end = start + level_size;
                    if end > exact_index {
                        self.levels[level].remove(i);
                        index_opt = Some(start);
                        break;
                    }
                }
            }
        }

        Some(unsafe { BlockAddr::new(index_opt?, exact_addr.level()) })
    }

    pub fn deallocate(&mut self, addr: BlockAddr) {
        // See if block matches with a sibling - if so, join them into a larger block, and populate
        // this all the way to the top level
        let mut index = addr.index();
        let mut level = addr.level().0;
        loop {
            while level >= self.levels.len() {
                self.levels.push(Vec::new());
            }

            let level_size = 1 << level;
            let next_size = level_size << 1;

            let mut found = false;
            let mut i = 0;
            while i < self.levels[level].len() {
                let level_index = self.levels[level][i];
                if index % next_size == 0 && index + level_size == level_index {
                    self.levels[level].remove(i);
                    found = true;
                    break;
                } else if level_index % next_size == 0 && level_index + level_size == index {
                    self.levels[level].remove(i);
                    index = level_index;
                    found = true;
                    break;
                }
                i += 1;
            }

            if !found {
                self.levels[level].push(index);
                return;
            }

            level += 1;
        }
    }
}

#[repr(C, packed)]
pub struct AllocEntry {
    index: Le<u64>,
    count: Le<i64>,
}

impl AllocEntry {
    pub fn new(index: u64, count: i64) -> Self {
        Self {
            index: index.into(),
            count: count.into(),
        }
    }

    pub fn allocate(addr: BlockAddr) -> Self {
        Self::new(addr.index(), -addr.level().blocks())
    }

    pub fn deallocate(addr: BlockAddr) -> Self {
        Self::new(addr.index(), addr.level().blocks())
    }

    pub fn index(&self) -> u64 {
        self.index.to_ne()
    }

    pub fn count(&self) -> i64 {
        self.count.to_ne()
    }

    pub fn is_null(&self) -> bool {
        self.count() == 0
    }
}

impl Clone for AllocEntry {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for AllocEntry {}

impl Default for AllocEntry {
    fn default() -> Self {
        Self {
            index: 0.into(),
            count: 0.into(),
        }
    }
}

impl fmt::Debug for AllocEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let index = self.index();
        let count = self.count();
        f.debug_struct("AllocEntry")
            .field("index", &index)
            .field("count", &count)
            .finish()
    }
}

/// Alloc log node
#[repr(C, packed)]
pub struct AllocList {
    pub prev: BlockPtr<AllocList>,
    pub entries: [AllocEntry; ALLOC_LIST_ENTRIES],
}

unsafe impl BlockTrait for AllocList {
    fn empty(level: BlockLevel) -> Option<Self> {
        if level.0 == 0 {
            Some(Self {
                prev: BlockPtr::default(),
                entries: [AllocEntry::default(); ALLOC_LIST_ENTRIES],
            })
        } else {
            None
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

    assert_eq!(alloc.allocate(BlockLevel::default()), None);

    alloc.deallocate(unsafe { BlockAddr::new(1, BlockLevel::default()) });
    assert_eq!(
        alloc.allocate(BlockLevel::default()),
        Some(unsafe { BlockAddr::new(1, BlockLevel::default()) })
    );
    assert_eq!(alloc.allocate(BlockLevel::default()), None);

    for addr in 1023..2048 {
        alloc.deallocate(unsafe { BlockAddr::new(addr, BlockLevel::default()) });
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
        assert_eq!(
            alloc.allocate(BlockLevel::default()),
            Some(unsafe { BlockAddr::new(addr, BlockLevel::default()) })
        );
    }
    assert_eq!(alloc.allocate(BlockLevel::default()), None);

    assert_eq!(alloc.levels.len(), 11);
    for level in 0..alloc.levels.len() {
        assert_eq!(alloc.levels[level], []);
    }
}
