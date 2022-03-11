use core::{marker::PhantomData, mem, ops, slice};
use redox_simple_endian::*;

use crate::{BlockPtr, BlockRaw};

// 1 << 8 = 256, this is the number of entries in a TreeList
const TREE_LIST_SHIFT: u32 = 8;

// Tree with 4 levels
pub type Tree = TreeList<TreeList<TreeList<TreeList<BlockRaw>>>>;

#[derive(Clone, Copy, Debug, Default)]
pub struct TreeData<T> {
    id: u32,
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

#[repr(packed)]
pub struct TreeList<T> {
    pub ptrs: [BlockPtr<T>; 1 << TREE_LIST_SHIFT],
}

impl<T> Default for TreeList<T> {
    fn default() -> Self {
        Self {
            ptrs: [BlockPtr::default(); 1 << TREE_LIST_SHIFT],
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

#[repr(packed)]
pub struct TreePtr<T> {
    id: u32le,
    phantom: PhantomData<T>,
}

impl<T> TreePtr<T> {
    pub fn root() -> Self {
        Self::new(1)
    }

    pub fn new(id: u32) -> Self {
        Self {
            id: id.into(),
            phantom: PhantomData,
        }
    }

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
        { self.id }.to_native()
    }

    pub fn is_null(&self) -> bool {
        self.id() == 0
    }

    pub fn indexes(&self) -> (usize, usize, usize, usize) {
        const SHIFT: u32 = TREE_LIST_SHIFT;
        const NUM: u32 = 1 << SHIFT;
        const MASK: u32 = NUM - 1;
        let id = self.id();
        (
            ((id >> (3 * SHIFT)) & MASK) as usize,
            ((id >> (2 * SHIFT)) & MASK) as usize,
            ((id >> SHIFT) & MASK) as usize,
            (id & MASK) as usize,
        )
    }
}

impl<T> Clone for TreePtr<T> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            phantom: PhantomData,
        }
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

#[test]
fn tree_list_size_test() {
    assert_eq!(
        mem::size_of::<TreeList<BlockRaw>>(),
        crate::BLOCK_SIZE as usize
    );
}
