use alloc::vec::Vec;
use core::{fmt, mem, ops, slice};
use endian_num::Le;

use crate::{BlockAddr, BlockLevel, BlockPtr, BlockTrait, BLOCK_SIZE};

pub const ALLOC_LIST_ENTRIES: usize =
    (BLOCK_SIZE as usize - mem::size_of::<BlockPtr<AllocList>>()) / mem::size_of::<AllocEntry>();

/// The RedoxFS block allocator. This struct manages all "data" blocks in RedoxFS
/// (i.e, all blocks that aren't reserved or part of the header chain).
///
/// [`Allocator`] can allocate blocks of many "levels"---that is, it can
/// allocate multiple consecutive [`BLOCK_SIZE`] blocks in one operation.
///
/// This reduces the amount of memory that the [`Allocator`] uses:
/// Instead of storing the index of each free [`BLOCK_SIZE`] block,
/// the `levels` array can keep track of higher-level blocks, splitting
/// them when a smaller block is requested.
///
/// Higher-level blocks also allow us to more efficiently allocate memory
/// for large files.
#[derive(Clone, Default)]
pub struct Allocator {
    /// This array keeps track of all free blocks of each level,
    /// and is initialized using the AllocList chain when we open the filesystem.
    ///
    /// Every element of the outer array represents a block level:
    /// - item 0: free level 0 blocks (with size [`BLOCK_SIZE`])
    /// - item 1: free level 1 blocks (with size 2*[`BLOCK_SIZE`])
    /// - item 2: free level 2 blocks (with size 4*[`BLOCK_SIZE`])
    /// ...and so on.
    ///
    /// Each inner array contains a list of free block indices,
    levels: Vec<Vec<u64>>,
}

impl Allocator {
    pub fn levels(&self) -> &Vec<Vec<u64>> {
        &self.levels
    }

    /// Count the number of free [`BLOCK_SIZE`] available to this [`Allocator`].
    pub fn free(&self) -> u64 {
        let mut free = 0;
        for level in 0..self.levels.len() {
            let level_size = 1 << level;
            free += self.levels[level].len() as u64 * level_size;
        }
        free
    }

    /// Find a free block of the given level, mark it as "used", and return its address.
    /// Returns [`None`] if there are no free blocks with this level.
    pub fn allocate(&mut self, block_level: BlockLevel) -> Option<BlockAddr> {
        // First, find the lowest level with a free block
        let mut index_opt = None;
        let mut level = block_level.0;
        // Start searching at the level we want. Smaller levels are too small!
        while level < self.levels.len() {
            if !self.levels[level].is_empty() {
                index_opt = self.levels[level].pop();
                break;
            }
            level += 1;
        }

        // If a free block was found, split it until we find a usable block of the right level.
        // The left side of the split block is kept free, and the right side is allocated.
        let index = index_opt?;
        while level > block_level.0 {
            level -= 1;
            let level_size = 1 << level;
            self.levels[level].push(index + level_size);
        }

        Some(unsafe { BlockAddr::new(index, block_level) })
    }

    /// Try to allocate the exact block specified, making all necessary splits.
    /// Returns [`None`] if this some (or all) of this block is already allocated.
    ///
    /// Note that [`BlockAddr`] encodes the blocks location _and_ level.
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

    /// Deallocate the given block, marking it "free" so that it can be re-used later.
    pub fn deallocate(&mut self, addr: BlockAddr) {
        // When we deallocate, we check if block we're deallocating has a free sibling.
        // If it does, we join the two to create one free block in the next (higher) level.
        //
        // We repeat this until we no longer have a sibling to join.
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
            // look at all free blocks in the current level...
            while i < self.levels[level].len() {
                // index of the second block we're looking at
                let level_index = self.levels[level][i];

                // - the block we just freed aligns with the next largest block, and
                // - the second block we're looking at is the right sibling of this block
                if index % next_size == 0 && index + level_size == level_index {
                    // "alloc" the next highest block, repeat deallocation process.
                    self.levels[level].remove(i);
                    found = true;
                    break;
                // - the index of this block doesn't align with the next largest block, and
                // - the block we're looking at is the left neighbor of this block
                } else if level_index % next_size == 0 && level_index + level_size == index {
                    // "alloc" the next highest block, repeat deallocation process.
                    self.levels[level].remove(i);
                    index = level_index; // index moves to left block
                    found = true;
                    break;
                }
                i += 1;
            }

            // We couldn't find a higher block,
            // deallocate this one and finish
            if !found {
                self.levels[level].push(index);
                return;
            }

            // repeat deallocation process on the
            // higher-level block we just created.
            level += 1;
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct AllocEntry {
    /// The index of the first block this [`AllocEntry`] refers to
    index: Le<u64>,

    /// The number of blocks after (and including) `index` that are are free or used.
    /// If negative, they are used; if positive, they are free.
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

/// A node in the allocation chain.
#[repr(C, packed)]
pub struct AllocList {
    /// A pointer to the previous AllocList.
    /// If this is the null pointer, this is the first element of the chain.
    pub prev: BlockPtr<AllocList>,

    /// Allocation entries.
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
            assert_eq!(alloc.levels[level], [0u64; 0]);
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
        assert_eq!(alloc.levels[level], [0u64; 0]);
    }
}
