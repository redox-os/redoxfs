use core::{mem, ops, slice, str};

use crate::{Node, TreePtr};

#[repr(packed)]
pub struct DirEntry {
    node_ptr: TreePtr<Node>,
    name: [u8; 252],
}

impl DirEntry {
    pub fn new(node_ptr: TreePtr<Node>, name: &str) -> Option<DirEntry> {
        let mut entry = DirEntry {
            node_ptr,
            ..Default::default()
        };

        if name.len() > entry.name.len() {
            return None;
        }

        entry.name[..name.len()].copy_from_slice(name.as_bytes());

        Some(entry)
    }

    pub fn node_ptr(&self) -> TreePtr<Node> {
        self.node_ptr
    }

    pub fn name(&self) -> Option<&str> {
        let mut len = 0;
        while len < self.name.len() {
            if self.name[len] == 0 {
                break;
            }
            len += 1;
        }
        //TODO: report utf8 error?
        str::from_utf8(&self.name[..len]).ok()
    }
}

impl Clone for DirEntry {
    fn clone(&self) -> Self {
        Self {
            node_ptr: self.node_ptr,
            name: self.name,
        }
    }
}

impl Copy for DirEntry {}

impl Default for DirEntry {
    fn default() -> Self {
        Self {
            node_ptr: TreePtr::default(),
            name: [0; 252],
        }
    }
}

#[repr(packed)]
pub struct DirList {
    pub entries: [DirEntry; 16],
}

impl DirList {
    pub fn is_empty(&self) -> bool {
        for entry in self.entries.iter() {
            if !entry.node_ptr().is_null() {
                return false;
            }
        }
        true
    }
}

impl Default for DirList {
    fn default() -> Self {
        Self {
            entries: [DirEntry::default(); 16],
        }
    }
}

impl ops::Deref for DirList {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self as *const DirList as *const u8,
                mem::size_of::<DirList>(),
            ) as &[u8]
        }
    }
}

impl ops::DerefMut for DirList {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self as *mut DirList as *mut u8, mem::size_of::<DirList>())
                as &mut [u8]
        }
    }
}

#[test]
fn dir_list_size_test() {
    assert_eq!(mem::size_of::<DirList>(), crate::BLOCK_SIZE as usize);
}
