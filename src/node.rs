use collections::Vec;

use core::{fmt, mem, ops, slice, str};

use super::Extent;

/// A file/folder node
#[repr(packed)]
pub struct Node {
    pub name: [u8; 256],
    pub mode: u64,
    pub next: u64,
    pub extents: [Extent; 15],
}

impl Node {
    pub const MODE_MASK: u64 = 0xF000;
    pub const MODE_FILE: u64 = 0x8000;
    pub const MODE_DIR: u64 = 0x4000;

    pub fn default() -> Node {
        Node {
            name: [0; 256],
            mode: 0,
            next: 0,
            extents: [Extent::default(); 15]
        }
    }

    pub fn new(name: &str, mode: u64) -> Node {
        let mut bytes = [0; 256];
        for (mut b, c) in bytes.iter_mut().zip(name.bytes()) {
            *b = c;
        }

        Node {
            name: bytes,
            mode: mode,
            next: 0,
            extents: [Extent::default(); 15]
        }
    }

    pub fn name(&self) -> Result<&str, str::Utf8Error> {
        let mut len = 0;

        for &b in self.name.iter() {
            if b == 0 {
                break;
            }
            len += 1;
        }

        str::from_utf8(&self.name[..len])
    }

    pub fn size(&self) -> u64 {
        self.extents.iter().fold(0, |size, extent| size + extent.length)
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let extents: Vec<&Extent> = self.extents.iter().filter(|extent| -> bool { extent.length > 0 }).collect();
        f.debug_struct("Node")
            .field("name", &self.name())
            .field("mode", &self.mode)
            .field("next", &self.next)
            .field("extents", &extents)
            .finish()
    }
}

impl ops::Deref for Node {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self as *const Node as *const u8, mem::size_of::<Node>()) as &[u8]
        }
    }
}

impl ops::DerefMut for Node {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self as *mut Node as *mut u8, mem::size_of::<Node>()) as &mut [u8]
        }
    }
}

#[test]
fn node_size_test(){
    assert!(mem::size_of::<Node>() <= 512);
}
