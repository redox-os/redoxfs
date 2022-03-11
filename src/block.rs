use core::{fmt, marker::PhantomData, mem, ops, slice};
use redox_simple_endian::*;

use crate::BLOCK_SIZE;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockData<T> {
    addr: u64,
    data: T,
}

impl<T> BlockData<T> {
    pub fn new(addr: u64, data: T) -> Self {
        Self { addr, data }
    }

    pub fn addr(&self) -> u64 {
        self.addr
    }

    #[must_use = "don't forget to de-allocate old block address"]
    pub fn swap_addr(&mut self, addr: u64) -> u64 {
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

    pub fn into_data(self) -> T {
        self.data
    }
}

impl<T: ops::Deref<Target = [u8]>> BlockData<T> {
    pub fn create_ptr(&self) -> BlockPtr<T> {
        BlockPtr {
            addr: self.addr.into(),
            hash: seahash::hash(self.data.deref()).into(),
            phantom: PhantomData,
        }
    }
}

#[repr(packed)]
pub struct BlockList<T> {
    pub ptrs: [BlockPtr<T>; 256],
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

impl<T> Default for BlockList<T> {
    fn default() -> Self {
        Self {
            ptrs: [BlockPtr::default(); 256],
        }
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

#[repr(packed)]
pub struct BlockPtr<T> {
    addr: u64le,
    hash: u64le,
    phantom: PhantomData<T>,
}

impl<T> BlockPtr<T> {
    pub fn addr(&self) -> u64 {
        { self.addr }.to_native()
    }

    pub fn hash(&self) -> u64 {
        { self.hash }.to_native()
    }

    pub fn is_null(&self) -> bool {
        self.addr() == 0
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
        Self {
            addr: self.addr,
            hash: self.hash,
            phantom: PhantomData,
        }
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

#[repr(packed)]
pub struct BlockRaw([u8; BLOCK_SIZE as usize]);

impl Clone for BlockRaw {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Default for BlockRaw {
    fn default() -> Self {
        Self([0; BLOCK_SIZE as usize])
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
