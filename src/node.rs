use std::{mem, slice};
use std::ops::{Deref, DerefMut};

use super::Extent;

/// A file/folder node
#[repr(packed)]
pub struct Node {
    pub name: [u8; 256],
    pub extents: [Extent; 16],
}

impl Node {
    pub fn new() -> Node {
        Node {
            name: [0; 256],
            extents: [Extent::default(); 16]
        }
    }
}

impl Deref for Node {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self as *const Node as *const u8, mem::size_of::<Node>()) as &[u8]
        }
    }
}

impl DerefMut for Node {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self as *mut Node as *mut u8, mem::size_of::<Node>()) as &mut [u8]
        }
    }
}
