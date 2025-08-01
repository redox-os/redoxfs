use core::{fmt, marker::PhantomData, mem, ops, slice};
use endian_num::Le;

use crate::BLOCK_SIZE;

const BLOCK_LIST_ENTRIES: usize = BLOCK_SIZE as usize / mem::size_of::<BlockPtr<BlockRaw>>();

/// An address of a data block.
///
/// This encodes a block's position _and_ [`BlockLevel`]:
/// the first four bits of this `u64` encode the block's level,
/// the next four bits indicates decompression level,
/// the rest encode its index.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockAddr(u64);

impl BlockAddr {
    const INDEX_SHIFT: u64 = 8;
    const DECOMP_LEVEL_MASK: u64 = 0xF0;
    const DECOMP_LEVEL_SHIFT: u64 = 4;
    const LEVEL_MASK: u64 = 0xF;

    // Unsafe because this can create invalid blocks
    pub(crate) unsafe fn new(index: u64, meta: BlockMeta) -> Self {
        // Level must fit within LEVEL_MASK
        if meta.level.0 > Self::LEVEL_MASK as usize {
            panic!("block level too large");
        }

        // Decomp level must fit within DECOMP_LEVEL_MASK
        let decomp_level = meta.decomp_level.unwrap_or_default();
        if (decomp_level.0 << Self::DECOMP_LEVEL_SHIFT) > Self::DECOMP_LEVEL_MASK as usize {
            panic!("decompressed block level too large");
        }

        // Index must not use the metadata bits
        let inner = index
            .checked_shl(Self::INDEX_SHIFT as u32)
            .expect("block index too large")
            | ((decomp_level.0 as u64) << Self::DECOMP_LEVEL_SHIFT)
            | (meta.level.0 as u64);
        Self(inner)
    }

    pub fn null(meta: BlockMeta) -> Self {
        unsafe { Self::new(0, meta) }
    }

    pub fn index(&self) -> u64 {
        // The first four bits store the level
        self.0 >> Self::INDEX_SHIFT
    }

    pub fn level(&self) -> BlockLevel {
        // The first four bits store the level
        BlockLevel((self.0 & Self::LEVEL_MASK) as usize)
    }

    pub fn decomp_level(&self) -> Option<BlockLevel> {
        let value = (self.0 & Self::DECOMP_LEVEL_MASK) >> Self::DECOMP_LEVEL_SHIFT;
        if value != 0 {
            Some(BlockLevel(value as usize))
        } else {
            None
        }
    }

    pub fn meta(&self) -> BlockMeta {
        BlockMeta {
            level: self.level(),
            decomp_level: self.decomp_level(),
        }
    }

    pub fn is_null(&self) -> bool {
        self.index() == 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct BlockMeta {
    pub(crate) level: BlockLevel,
    pub(crate) decomp_level: Option<BlockLevel>,
}

impl BlockMeta {
    pub fn new(level: BlockLevel) -> Self {
        Self {
            level,
            decomp_level: None,
        }
    }

    pub fn new_compressed(level: BlockLevel, decomp_level: BlockLevel) -> Self {
        Self {
            level,
            decomp_level: Some(decomp_level),
        }
    }
}

/// The size of a block.
///
/// Level 0 blocks are blocks of [`BLOCK_SIZE`] bytes.
/// A level 1 block consists of two consecutive level 0 blocks.
/// A level n block consists of two consecutive level n-1 blocks.
///
/// See [`crate::Allocator`] docs for more details.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockLevel(pub(crate) usize);

impl BlockLevel {
    /// Returns the smallest block level that can contain
    /// the given number of bytes.
    pub(crate) fn for_bytes(bytes: u64) -> Self {
        if bytes == 0 {
            return BlockLevel(0);
        }
        let level = bytes
            .div_ceil(BLOCK_SIZE)
            .next_power_of_two()
            .trailing_zeros() as usize;
        BlockLevel(level)
    }

    /// The number of [`BLOCK_SIZE`] blocks (i.e, level 0 blocks)
    /// in a block of this level
    pub fn blocks<T: From<u32>>(self) -> T {
        T::from(1u32 << self.0)
    }

    /// The number of bytes in a block of this level
    pub fn bytes(self) -> u64 {
        BLOCK_SIZE << self.0
    }
}

pub unsafe trait BlockTrait {
    /// Create an empty block of this type.
    fn empty(level: BlockLevel) -> Option<Self>
    where
        Self: Sized;
}

/// A [`BlockAddr`] and the data it points to.
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

    pub fn data(&self) -> &T {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }

    pub(crate) unsafe fn into_parts(self) -> (BlockAddr, T) {
        (self.addr, self.data)
    }

    /// Set the address of this [`BlockData`] to `addr`, returning this
    /// block's old address. This method does not update block data.
    ///
    /// `addr` must point to a block with the same level as this block.
    #[must_use = "don't forget to de-allocate old block address"]
    pub fn swap_addr(&mut self, addr: BlockAddr) -> BlockAddr {
        // Address levels must match
        assert_eq!(self.addr.level(), addr.level());
        let old = self.addr;
        self.addr = addr;
        old
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
        self.ptrs.iter().all(|ptr| ptr.is_null())
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

/// An address of a data block, along with a checksum of its data.
///
/// This encodes a block's position _and_ [`BlockLevel`].
/// the first four bits of `addr` encode the block's level,
/// the rest encode its index.
///
/// Also see [`BlockAddr`].
#[repr(C, packed)]
pub struct BlockPtr<T> {
    addr: Le<u64>,
    hash: Le<u64>,
    phantom: PhantomData<T>,
}

impl<T> BlockPtr<T> {
    pub fn null(meta: BlockMeta) -> Self {
        Self {
            addr: BlockAddr::null(meta).0.into(),
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

    pub fn marker(level: u8) -> Self {
        assert!(level <= 0xF);
        Self {
            addr: (0xFFFF_FFFF_FFFF_FFF0 | (level as u64)).into(),
            hash: u64::MAX.into(),
            phantom: PhantomData,
        }
    }

    pub fn is_marker(&self) -> bool {
        (self.addr.to_ne() | 0xF) == u64::MAX && self.hash.to_ne() == u64::MAX
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
#[derive(Clone)]
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

#[test]
fn block_ptr_marker_test() {
    let ptr = BlockPtr::<BlockRaw>::marker(0);
    assert_eq!(ptr.addr().level().0, 0);
    assert!(ptr.is_marker());

    let ptr = BlockPtr::<BlockRaw>::marker(2);
    assert_eq!(ptr.addr().level().0, 2);
    assert!(ptr.is_marker());
}
