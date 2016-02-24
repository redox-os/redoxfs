use std::{mem, slice};
use std::ops::{Deref, DerefMut};

use super::Extent;

/// The header of the filesystem
#[repr(packed)]
pub struct Header {
    pub signature: [u8; 8],
    pub version: u64,
    pub free_space: Extent,
    pub padding: [u8; 224],
    pub extents: [Extent; 16],
}

impl Header {
    pub fn new() -> Header {
        Header {
            signature: [0; 8],
            version: 0,
            free_space: Extent::default(),
            padding: [0; 224],
            extents: [Extent::default(); 16]
        }
    }

    pub fn valid(&self) -> bool {
        &self.signature == b"REDOXFS\0" && self.version == 1
    }
}

impl Deref for Header {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self as *const Header as *const u8, mem::size_of::<Header>()) as &[u8]
        }
    }
}

impl DerefMut for Header {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self as *mut Header as *mut u8, mem::size_of::<Header>()) as &mut [u8]
        }
    }
}
