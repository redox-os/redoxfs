use std::{fmt, mem, slice};
use std::ops::{Deref, DerefMut};

use uuid::Uuid;

use {BLOCK_SIZE, SIGNATURE, VERSION};

/// The header of the filesystem
#[derive(Clone, Copy)]
#[repr(packed)]
pub struct Header {
    /// Signature, should be SIGNATURE
    pub signature: [u8; 8],
    /// Version, should be VERSION
    pub version: u64,
    /// Disk ID, a 128-bit unique identifier
    pub uuid: [u8; 16],
    /// Disk size, in number of BLOCK_SIZE sectors
    pub size: u64,
    /// Block of root node
    pub root: u64,
    /// Block of free space node
    pub free: u64,
    /// Padding
    pub padding: [u8; BLOCK_SIZE as usize - 56]
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
            padding: [0; BLOCK_SIZE as usize - 56]
        }
    }

    pub fn new(size: u64, root: u64, free: u64) -> Header {
        let uuid = Uuid::new_v4();
        Header {
            signature: *SIGNATURE,
            version: VERSION,
            uuid: *uuid.as_bytes(),
            size: size,
            root: root,
            free: free,
            padding: [0; BLOCK_SIZE as usize - 56]
        }
    }

    pub fn valid(&self) -> bool {
        &self.signature == SIGNATURE && self.version == VERSION
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            f.debug_struct("Header")
                .field("signature", &self.signature)
                .field("version", &self.version)
                .field("uuid", &self.uuid)
                .field("size", &self.size)
                .field("root", &self.root)
                .field("free", &self.free)
                .finish()
        }
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
fn header_size_test() {
    assert_eq!(mem::size_of::<Header>(), BLOCK_SIZE as usize);
}
