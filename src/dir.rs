use alloc::{boxed::Box, vec};
use core::{mem, ops, slice, str};

use crate::{BlockLevel, BlockTrait, Node, TreePtr, RECORD_LEVEL, DIR_ENTRY_MAX_LENGTH};

#[repr(C, packed)]
pub struct DirEntry {
    node_ptr: TreePtr<Node>,
    name: [u8; DIR_ENTRY_MAX_LENGTH],
}

impl DirEntry {
    pub fn new(node_ptr: TreePtr<Node>, name: &str) -> DirEntry {
        let mut entry = DirEntry {
            node_ptr,
            ..Default::default()
        };

        entry.name[..name.len()].copy_from_slice(name.as_bytes());

        entry
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
        *self
    }
}

impl Copy for DirEntry {}

impl Default for DirEntry {
    fn default() -> Self {
        Self {
            node_ptr: TreePtr::default(),
            name: [0; DIR_ENTRY_MAX_LENGTH],
        }
    }
}

//TODO: this is a box to prevent stack overflows
pub struct DirList {
    pub entries: Box<[DirEntry]>,
}

unsafe impl BlockTrait for DirList {
    fn empty(level: BlockLevel) -> Option<Self> {
        if level.0 <= RECORD_LEVEL {
            let entries = level.bytes() as usize / mem::size_of::<DirEntry>();
            Some(Self {
                entries: vec![DirEntry::default(); entries].into_boxed_slice(),
            })
        } else {
            None
        }
    }
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

impl ops::Deref for DirList {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self.entries.as_ptr() as *const u8,
                self.entries.len() * mem::size_of::<DirEntry>(),
            ) as &[u8]
        }
    }
}

impl ops::DerefMut for DirList {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self.entries.as_mut_ptr() as *mut u8,
                self.entries.len() * mem::size_of::<DirEntry>(),
            ) as &mut [u8]
        }
    }
}

#[test]
fn dir_list_size_test() {
    use core::ops::Deref;
    for level_i in 0..RECORD_LEVEL {
        let level = BlockLevel(level_i);
        assert_eq!(
            DirList::empty(level).unwrap().deref().len(),
            level.bytes() as usize
        );
    }
}
