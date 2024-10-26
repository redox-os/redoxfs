use core::{fmt, marker::PhantomData, mem, ops, slice};
use endian_num::Le;

use crate::BLOCK_SIZE;

const BLOCK_LIST_ENTRIES: usize = BLOCK_SIZE as usize / mem::size_of::<BlockPtr<BlockRaw>>();

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockAddr(u64);

impl BlockAddr {
    // Unsafe because this can create invalid blocks
    pub(crate) unsafe fn new(index: u64, level: BlockLevel) -> Self {
        // Level must only use the lowest four bits
        if level.0 > 0xF {
            panic!("block level used more than four bits");
        }

        // Index must not use the highest four bits
        let inner = index
            .checked_shl(4)
            .expect("block index used highest four bits")
            | (level.0 as u64);
        Self(inner)
    }

    pub fn null(level: BlockLevel) -> Self {
        unsafe { Self::new(0, level) }
    }

    pub fn index(&self) -> u64 {
        // The first four bits store the level
        self.0 >> 4
    }

    pub fn level(&self) -> BlockLevel {
        // The first four bits store the level
        BlockLevel((self.0 & 0xF) as usize)
    }

    pub fn is_null(&self) -> bool {
        self.index() == 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockLevel(pub(crate) usize);

impl BlockLevel {
    pub(crate) fn for_bytes(bytes: u64) -> Self {
        if bytes == 0 {
            return BlockLevel(0);
        }
        let level = bytes.div_ceil(BLOCK_SIZE)
            .next_power_of_two()
            .trailing_zeros() as usize;
        BlockLevel(level)
    }

    pub fn blocks(self) -> i64 {
        1 << self.0
    }

    pub fn bytes(self) -> u64 {
        BLOCK_SIZE << self.0
    }
}

pub unsafe trait BlockTrait {
    fn empty(level: BlockLevel) -> Option<Self>
    where
        Self: Sized;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockData<T> {
    addr: BlockAddr,
    data: T,
}

impl<T> BlockData<T> {
    pub fn new(addr: BlockAddr, data: T) -> Self {
        Self { addr, data }
    }

    pub fn addr(&self) -> BlockAddr {
        self.addr
    }

    #[must_use = "don't forget to de-allocate old block address"]
    pub fn swap_addr(&mut self, addr: BlockAddr) -> BlockAddr {
        // Address levels must match
        assert_eq!(self.addr.level(), addr.level());
        let old = self.addr;
        self.addr = addr;
        old
    }

    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }

    pub(crate) unsafe fn into_parts(self) -> (BlockAddr, T) {
        (self.addr, self.data)
    }
}

impl<T: BlockTrait> BlockData<T> {
    pub fn empty(addr: BlockAddr) -> Option<Self> {
        let empty = T::empty(addr.level())?;
        Some(Self::new(addr, empty))
    }
}

impl<T: ops::Deref<Target = [u8]>> BlockData<T> {
    pub fn create_ptr(&self) -> BlockPtr<T> {
        BlockPtr {
            addr: self.addr.0.into(),
            hash: seahash::hash(self.data.deref()).into(),
            phantom: PhantomData,
        }
    }
}

#[repr(C, packed)]
pub struct BlockList<T> {
    pub ptrs: [BlockPtr<T>; BLOCK_LIST_ENTRIES],
}

unsafe impl<T> BlockTrait for BlockList<T> {
    fn empty(level: BlockLevel) -> Option<Self> {
        if level.0 == 0 {
            Some(Self {
                ptrs: [BlockPtr::default(); BLOCK_LIST_ENTRIES],
            })
        } else {
            None
        }
    }
}

impl<T> BlockList<T> {
    pub fn is_empty(&self) -> bool {
        for ptr in self.ptrs.iter() {
            if !ptr.is_null() {
                return false;
            }
        }
        true
    }
}

impl<T> ops::Deref for BlockList<T> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const BlockList<T> as *const u8,
                mem::size_of::<BlockList<T>>(),
            ) as &[u8]
        }
    }
}

impl<T> ops::DerefMut for BlockList<T> {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self as *mut BlockList<T> as *mut u8,
                mem::size_of::<BlockList<T>>(),
            ) as &mut [u8]
        }
    }
}

#[repr(C, packed)]
pub struct BlockPtr<T> {
    addr: Le<u64>,
    hash: Le<u64>,
    phantom: PhantomData<T>,
}

impl<T> BlockPtr<T> {
    pub fn null(level: BlockLevel) -> Self {
        Self {
            addr: BlockAddr::null(level).0.into(),
            hash: 0.into(),
            phantom: PhantomData,
        }
    }

    pub fn addr(&self) -> BlockAddr {
        BlockAddr(self.addr.to_ne())
    }

    pub fn hash(&self) -> u64 {
        self.hash.to_ne()
    }

    pub fn is_null(&self) -> bool {
        self.addr().is_null()
    }

    /// Cast BlockPtr to another type
    ///
    /// # Safety
    /// Unsafe because it can be used to transmute types
    pub unsafe fn cast<U>(self) -> BlockPtr<U> {
        BlockPtr {
            addr: self.addr,
            hash: self.hash,
            phantom: PhantomData,
        }
    }

    #[must_use = "the returned pointer should usually be deallocated"]
    pub fn clear(&mut self) -> BlockPtr<T> {
        let mut ptr = Self::default();
        mem::swap(self, &mut ptr);
        ptr
    }
}

impl<T> Clone for BlockPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for BlockPtr<T> {}

impl<T> Default for BlockPtr<T> {
    fn default() -> Self {
        Self {
            addr: 0.into(),
            hash: 0.into(),
            phantom: PhantomData,
        }
    }
}

impl<T> fmt::Debug for BlockPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let addr = self.addr();
        let hash = self.hash();
        f.debug_struct("BlockPtr")
            .field("addr", &addr)
            .field("hash", &hash)
            .finish()
    }
}

#[repr(C, packed)]
pub struct BlockRaw([u8; BLOCK_SIZE as usize]);

unsafe impl BlockTrait for BlockRaw {
    fn empty(level: BlockLevel) -> Option<Self> {
        if level.0 == 0 {
            Some(Self([0; BLOCK_SIZE as usize]))
        } else {
            None
        }
    }
}

impl Clone for BlockRaw {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl ops::Deref for BlockRaw {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl ops::DerefMut for BlockRaw {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[test]
fn block_list_size_test() {
    assert_eq!(mem::size_of::<BlockList<BlockRaw>>(), BLOCK_SIZE as usize);
}

#[test]
fn block_raw_size_test() {
    assert_eq!(mem::size_of::<BlockRaw>(), BLOCK_SIZE as usize);
}
