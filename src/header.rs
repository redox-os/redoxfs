use core::{mem, slice};
use core::ops::{Deref, DerefMut};

/// The header of the filesystem
#[derive(Debug)]
#[repr(packed)]
pub struct Header {
    /// Signature, should be b"REDOXFS\0"
    pub signature: [u8; 8],
    /// Version, should be 1
    pub version: u64,
    /// Disk ID, a 128-byte unique identifier
    pub uuid: [u8; 16],
    /// Disk size, in 512-byte sectors
    pub size: u64,
    /// Block of root node
    pub root: u64,
    /// Block of free space node
    pub free: u64,
}

impl Header {
    pub fn default() -> Header {
        Header {
            signature: [0; 8],
            version: 0,
            uuid: [0; 16],
            size: 0,
            root: 0,
            free: 0,
        }
    }

    pub fn new(size: u64, root: u64, free: u64) -> Header {
        Header {
            signature: *b"RedoxFS\0",
            version: 1,
            uuid: [0; 16],
            size: size,
            root: root,
            free: free,
        }
    }

    pub fn valid(&self) -> bool {
        &self.signature == b"RedoxFS\0" && self.version == 1
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

#[test]
fn header_size_test(){
    assert!(mem::size_of::<Header>() <= 512);
}
