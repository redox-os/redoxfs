use collections::Vec;

use core::{fmt, mem, ops, slice, str};

use super::Extent;

/// A file/folder node
#[repr(packed)]
pub struct Node {
    pub mode: u16,
    pub user: u16,
    pub group: u16,
    pub name: [u8; 250],
    pub parent: u64,
    pub next: u64,
    pub extents: [Extent; 15],
}

impl Node {
    pub const MODE_TYPE: u16 = 0xF000;
    pub const MODE_FILE: u16 = 0x8000;
    pub const MODE_DIR: u16 = 0x4000;

    pub const MODE_PERM: u16 = 0x0FFF;

    pub fn default() -> Node {
        Node {
            mode: 0,
            user: 0,
            group: 0,
            name: [0; 250],
            parent: 0,
            next: 0,
            extents: [Extent::default(); 15],
        }
    }

    pub fn new(mode: u16, name: &str, parent: u64) -> Node {
        let mut bytes = [0; 250];
        for (mut b, c) in bytes.iter_mut().zip(name.bytes()) {
            *b = c;
        }

        Node {
            mode: mode,
            user: 0,
            group: 0,
            name: bytes,
            parent: parent,
            next: 0,
            extents: [Extent::default(); 15],
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

    pub fn is_dir(&self) -> bool {
        self.mode & Node::MODE_TYPE == Node::MODE_DIR
    }

    pub fn is_file(&self) -> bool {
        self.mode & Node::MODE_TYPE == Node::MODE_FILE
    }

    pub fn size(&self) -> u64 {
        self.extents.iter().fold(0, |size, extent| size + extent.length)
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let extents: Vec<&Extent> = self.extents.iter().filter(|extent| -> bool { extent.length > 0 }).collect();
        f.debug_struct("Node")
            .field("mode", &self.mode)
            .field("user", &self.user)
            .field("group", &self.group)
            .field("name", &self.name())
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
    assert_eq!(mem::size_of::<Node>(), 512);
}
