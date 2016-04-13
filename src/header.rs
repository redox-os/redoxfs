use std::{fmt, mem, slice};
use std::ops::{Deref, DerefMut};

/// The header of the filesystem
#[repr(packed)]
pub struct Header {
    /// Signature, should be b"RedoxFS\0"
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
    /// Padding
    pub padding: [u8; 456]
}

impl Header {
    pub const SIGNATURE: &'static [u8; 8] = b"RedoxFS\0";
    pub const VERSION: u64 = 1;

    pub fn default() -> Header {
        Header {
            signature: [0; 8],
            version: 0,
            uuid: [0; 16],
            size: 0,
            root: 0,
            free: 0,
            padding: [0; 456]
        }
    }

    pub fn new(size: u64, root: u64, free: u64) -> Header {
        Header {
            signature: *Header::SIGNATURE,
            version: Header::VERSION,
            uuid: [0; 16],
            size: size,
            root: root,
            free: free,
            padding: [0; 456]
        }
    }

    pub fn valid(&self) -> bool {
        &self.signature == Header::SIGNATURE && self.version == Header::VERSION
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
    assert_eq!(mem::size_of::<Header>(), 512);
}
