use std::{fmt, mem, ops, slice};

use super::{Extent, FileName, FileNameBuf};

/// A file/folder node
#[repr(packed)]
pub struct Node {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub ctime: u64,
    pub ctime_nsec: u32,
    pub mtime: u64,
    pub mtime_nsec: u32,
    pub name: FileNameBuf,
    pub parent: u64,
    pub next: u64,
    pub extents: [Extent; 15],
}

impl Node {
    pub const MODE_TYPE: u16 = 0xF000;
    pub const MODE_FILE: u16 = 0x8000;
    pub const MODE_DIR: u16 = 0x4000;
    pub const MODE_SYMLINK: u16 = 0xA000;

    pub const MODE_PERM: u16 = 0x0FFF;
    pub const MODE_EXEC: u16 = 0o1;
    pub const MODE_WRITE: u16 = 0o2;
    pub const MODE_READ: u16 = 0o4;

    pub fn default() -> Node {
        Node {
            mode: 0,
            uid: 0,
            gid: 0,
            ctime: 0,
            ctime_nsec: 0,
            mtime: 0,
            mtime_nsec: 0,
            name: FileNameBuf::default(),
            parent: 0,
            next: 0,
            extents: [Extent::default(); 15],
        }
    }

    pub fn new(mode: u16, name: &FileName, parent: u64, ctime: u64, ctime_nsec: u32) -> Node {
        let bytes = name.to_filename_buf();

        Node {
            mode: mode,
            uid: 0,
            gid: 0,
            ctime: ctime,
            ctime_nsec: ctime_nsec,
            mtime: ctime,
            mtime_nsec: ctime_nsec,
            name: bytes,
            parent: parent,
            next: 0,
            extents: [Extent::default(); 15],
        }
    }

    pub fn name(&self) -> &FileName {
        &self.name
    }

    pub fn is_dir(&self) -> bool {
        self.mode & Node::MODE_TYPE == Node::MODE_DIR
    }

    pub fn is_file(&self) -> bool {
        self.mode & Node::MODE_TYPE == Node::MODE_FILE
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & Node::MODE_TYPE == Node::MODE_SYMLINK
    }

    pub fn permission(&self, uid: u32, gid: u32, op: u16) -> bool {
        let mut perm = self.mode & 0o7;
        if self.uid == uid {
            perm |= (self.mode >> 6) & 0o7;
        }
        if self.gid == gid || gid == 0 {
            perm |= (self.mode >> 3) & 0o7;
        }
        if uid == 0 {
            perm |= 0o7;
        }
        perm & op == op
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
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("ctime", &self.ctime)
            .field("ctime_nsec", &self.ctime_nsec)
            .field("mtime", &self.mtime)
            .field("mtime_nsec", &self.mtime_nsec)
            .field("name", &self.name.as_str())
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
fn node_size_test() {
    assert_eq!(mem::size_of::<Node>(), 512);
}
