use core::{marker::PhantomData, mem, ops, slice};
use endian_num::Le;

use crate::{BlockLevel, BlockPtr, BlockRaw, BlockTrait};

// 1 << 8 = 256, this is the number of entries in a TreeList
const TREE_LIST_SHIFT: u32 = 8;
const TREE_LIST_ENTRIES: usize = (1 << TREE_LIST_SHIFT) - 2;

/// A tree with 4 levels
pub type Tree = TreeList<TreeList<TreeList<TreeList<BlockRaw>>>>;

/// A [`TreePtr`] and the contents of the block it references.
#[derive(Clone, Copy, Debug, Default)]
pub struct TreeData<T> {
    /// The value of the [`TreePtr`]
    id: u32,

    // The data
    data: T,
}

impl<T> TreeData<T> {
    pub fn new(id: u32, data: T) -> Self {
        Self { id, data }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }

    pub fn into_data(self) -> T {
        self.data
    }

    pub fn ptr(&self) -> TreePtr<T> {
        TreePtr {
            id: self.id.into(),
            phantom: PhantomData,
        }
    }
}

/// A list of pointers to blocks of type `T`.
/// This is one level of a [`Tree`], defined above.
#[repr(C, packed)]
pub struct TreeList<T> {
    pub ptrs: [BlockPtr<T>; TREE_LIST_ENTRIES],
    pub full_flags: [u128; 2],
}

impl<T> TreeList<T> {
    pub fn tree_list_is_full(&self) -> bool {
        self.full_flags[1] == u128::MAX & !(3 << 126) && self.full_flags[0] == u128::MAX
    }

    pub fn tree_list_is_empty(&self) -> bool {
        for ptr in self.ptrs.iter() {
            if !ptr.is_null() {
                return false;
            }
        }
        true
    }

    pub fn branch_is_full(&self, index: usize) -> bool {
        assert!(index < TREE_LIST_ENTRIES);
        let shift = index % 128;
        let full_flags_index = index / 128;
        self.full_flags[full_flags_index] & (1 << shift) != 0
    }

    pub fn set_branch_full(&mut self, index: usize, full: bool) {
        assert!(index < TREE_LIST_ENTRIES);
        let shift = index % 128;
        let full_flags_index = index / 128;

        if full {
            self.full_flags[full_flags_index] |= 1 << shift;
        } else {
            self.full_flags[full_flags_index] &= !(1 << shift);
        }
    }
}

unsafe impl<T> BlockTrait for TreeList<T> {
    fn empty(level: BlockLevel) -> Option<Self> {
        if level.0 == 0 {
            Some(Self {
                ptrs: [BlockPtr::default(); TREE_LIST_ENTRIES],
                full_flags: [0; 2],
            })
        } else {
            None
        }
    }
}

impl<T> ops::Deref for TreeList<T> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const TreeList<T> as *const u8,
                mem::size_of::<TreeList<T>>(),
            ) as &[u8]
        }
    }
}

impl<T> ops::DerefMut for TreeList<T> {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self as *mut TreeList<T> as *mut u8,
                mem::size_of::<TreeList<T>>(),
            ) as &mut [u8]
        }
    }
}

/// A pointer to an entry in a [`Tree`].
#[repr(C, packed)]
pub struct TreePtr<T> {
    id: Le<u32>,
    phantom: PhantomData<T>,
}

impl<T> TreePtr<T> {
    /// Get a [`TreePtr`] to the filesystem root
    /// directory's node.
    pub fn root() -> Self {
        Self::new(1)
    }

    pub fn new(id: u32) -> Self {
        Self {
            id: id.into(),
            phantom: PhantomData,
        }
    }

    /// Create a [`TreePtr`] from [`Tree`] indices,
    /// Where `indexes` is `(i3, i2, i1, i0)`.
    /// - `i3` is the index into the level 3 table,
    /// - `i2` is the index into the level 2 table at `i3`
    /// - ...and so on.
    pub fn from_indexes(indexes: (usize, usize, usize, usize)) -> Self {
        const SHIFT: u32 = TREE_LIST_SHIFT;
        let id = ((indexes.0 << (3 * SHIFT)) as u32)
            | ((indexes.1 << (2 * SHIFT)) as u32)
            | ((indexes.2 << SHIFT) as u32)
            | (indexes.3 as u32);
        Self {
            id: id.into(),
            phantom: PhantomData,
        }
    }

    pub fn id(&self) -> u32 {
        self.id.to_ne()
    }

    pub fn is_null(&self) -> bool {
        self.id() == 0
    }

    /// Get this indices of this [`TreePtr`] in a [`Tree`].
    /// Returns `(i3, i2, i1, i0)`:
    /// - `i3` is the index into the level 3 table,
    /// - `i2` is the index into the level 2 table at `i3`
    /// - ...and so on.
    pub fn indexes(&self) -> (usize, usize, usize, usize) {
        const SHIFT: u32 = TREE_LIST_SHIFT;
        const NUM: u32 = 1 << SHIFT;
        const MASK: u32 = NUM - 1;
        let id = self.id();

        let i3 = ((id >> (3 * SHIFT)) & MASK) as usize;
        let i2 = ((id >> (2 * SHIFT)) & MASK) as usize;
        let i1 = ((id >> SHIFT) & MASK) as usize;
        let i0 = (id & MASK) as usize;

        (i3, i2, i1, i0)
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        self.id.to_le_bytes()
    }

    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        let val = u32::from_le_bytes(bytes);
        Self {
            id: Le(val),
            phantom: PhantomData,
        }
    }
}

impl<T> Clone for TreePtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for TreePtr<T> {}

impl<T> Default for TreePtr<T> {
    fn default() -> Self {
        Self {
            id: 0.into(),
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{BlockAddr, BlockData};

    use super::*;

    #[test]
    fn tree_list_size_test() {
        assert_eq!(
            mem::size_of::<TreeList<BlockRaw>>(),
            crate::BLOCK_SIZE as usize
        );
    }

    #[test]
    fn tree_list_is_full_test() {
        let mut tree_list = TreeList::<BlockRaw>::empty(BlockLevel::default()).unwrap();
        assert!(!tree_list.tree_list_is_full());

        for i in 0..TREE_LIST_ENTRIES {
            assert!(!tree_list.branch_is_full(i));
            tree_list.set_branch_full(i, true);
            assert!(tree_list.branch_is_full(i));
        }

        assert!(tree_list.tree_list_is_full());

        for i in 0..TREE_LIST_ENTRIES {
            assert!(tree_list.branch_is_full(i));
            tree_list.set_branch_full(i, false);
            assert!(!tree_list.branch_is_full(i));
        }
    }

    fn mock_block(addr: u64) -> BlockPtr<BlockRaw> {
        let block_addr = unsafe { BlockAddr::new(addr, BlockLevel::default()) };
        BlockData::empty(block_addr).unwrap().create_ptr()
    }

    #[test]
    fn tree_list_is_empty() {
        let mut tree_list = TreeList::<BlockRaw>::empty(BlockLevel::default()).unwrap();
        assert!(tree_list.tree_list_is_empty());

        tree_list.ptrs[3] = mock_block(123);
        assert!(!tree_list.tree_list_is_empty());
    }

    #[test]
    fn tree_ptr_to_and_from_bytes() {
        let ptr: TreePtr<BlockRaw> = TreePtr::new(123456);
        let bytes = ptr.to_bytes();
        let ptr2: TreePtr<BlockRaw> = TreePtr::from_bytes(bytes);
        assert_eq!(ptr.id(), ptr2.id());
    }
}
