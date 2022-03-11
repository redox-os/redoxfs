use core::{fmt, mem, ops, slice};
use redox_simple_endian::*;

use crate::{BlockList, BlockPtr, BlockRaw};

pub enum NodeLevel {
    L0(usize),
    L1(usize, usize),
    L2(usize, usize, usize),
    L3(usize, usize, usize, usize),
    L4(usize, usize, usize, usize, usize),
}

impl NodeLevel {
    // Warning: this uses constant block offsets, make sure to sync with Node
    pub fn new(mut block_offset: u64) -> Option<Self> {
        // 1 << 8 = 256, this is the number of entries in a BlockList
        const SHIFT: u64 = 8;
        const NUM: u64 = 1 << SHIFT;
        const MASK: u64 = NUM - 1;

        const L0: u64 = 128;
        if block_offset < L0 {
            return Some(Self::L0((block_offset & MASK) as usize));
        } else {
            block_offset -= L0;
        }

        const L1: u64 = 64 * NUM;
        if block_offset < L1 {
            return Some(Self::L1(
                ((block_offset >> SHIFT) & MASK) as usize,
                (block_offset & MASK) as usize,
            ));
        } else {
            block_offset -= L1;
        }

        const L2: u64 = 32 * NUM * NUM;
        if block_offset < L2 {
            return Some(Self::L2(
                ((block_offset >> (2 * SHIFT)) & MASK) as usize,
                ((block_offset >> SHIFT) & MASK) as usize,
                (block_offset & MASK) as usize,
            ));
        } else {
            block_offset -= L2;
        }

        const L3: u64 = 16 * NUM * NUM * NUM;
        if block_offset < L3 {
            return Some(Self::L3(
                ((block_offset >> (3 * SHIFT)) & MASK) as usize,
                ((block_offset >> (2 * SHIFT)) & MASK) as usize,
                ((block_offset >> SHIFT) & MASK) as usize,
                (block_offset & MASK) as usize,
            ));
        } else {
            block_offset -= L3;
        }

        const L4: u64 = 12 * NUM * NUM * NUM * NUM;
        if block_offset < L4 {
            Some(Self::L4(
                ((block_offset >> (4 * SHIFT)) & MASK) as usize,
                ((block_offset >> (3 * SHIFT)) & MASK) as usize,
                ((block_offset >> (2 * SHIFT)) & MASK) as usize,
                ((block_offset >> SHIFT) & MASK) as usize,
                (block_offset & MASK) as usize,
            ))
        } else {
            None
        }
    }
}

type BlockListL1 = BlockList<BlockRaw>;
type BlockListL2 = BlockList<BlockListL1>;
type BlockListL3 = BlockList<BlockListL2>;
type BlockListL4 = BlockList<BlockListL3>;

/// A file/folder node
#[repr(packed)]
pub struct Node {
    pub mode: u16le,
    pub uid: u32le,
    pub gid: u32le,
    pub links: u32le,
    pub size: u64le,
    pub ctime: u64le,
    pub ctime_nsec: u32le,
    pub mtime: u64le,
    pub mtime_nsec: u32le,
    pub atime: u64le,
    pub atime_nsec: u32le,
    pub padding: [u8; 6],
    // 128 * BLOCK_SIZE (512 KiB, 4 KiB each)
    pub level0: [BlockPtr<BlockRaw>; 128],
    // 64 * 256 * BLOCK_SIZE (64 MiB, 1 MiB each)
    pub level1: [BlockPtr<BlockListL1>; 64],
    // 32 * 256 * 256 * BLOCK_SIZE (8 GiB, 256 MiB each)
    pub level2: [BlockPtr<BlockListL2>; 32],
    // 16 * 256 * 256 * 256 * BLOCK_SIZE (1 TiB, 64 GiB each)
    pub level3: [BlockPtr<BlockListL3>; 16],
    // 12 * 256 * 256 * 256 * 256 * BLOCK_SIZE (192 TiB, 16 TiB each)
    pub level4: [BlockPtr<BlockListL4>; 12],
}

impl Default for Node {
    fn default() -> Self {
        Self {
            mode: 0.into(),
            uid: 0.into(),
            gid: 0.into(),
            links: 0.into(),
            size: 0.into(),
            ctime: 0.into(),
            ctime_nsec: 0.into(),
            mtime: 0.into(),
            mtime_nsec: 0.into(),
            atime: 0.into(),
            atime_nsec: 0.into(),
            padding: [0; 6],
            level0: [BlockPtr::default(); 128],
            level1: [BlockPtr::default(); 64],
            level2: [BlockPtr::default(); 32],
            level3: [BlockPtr::default(); 16],
            level4: [BlockPtr::default(); 12],
        }
    }
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

    pub fn new(mode: u16, uid: u32, gid: u32, ctime: u64, ctime_nsec: u32) -> Self {
        Self {
            mode: mode.into(),
            uid: uid.into(),
            gid: gid.into(),
            links: 0.into(),
            ctime: ctime.into(),
            ctime_nsec: ctime_nsec.into(),
            mtime: ctime.into(),
            mtime_nsec: ctime_nsec.into(),
            atime: ctime.into(),
            atime_nsec: ctime_nsec.into(),
            ..Default::default()
        }
    }

    pub fn mode(&self) -> u16 {
        { self.mode }.to_native()
    }

    pub fn uid(&self) -> u32 {
        { self.uid }.to_native()
    }

    pub fn gid(&self) -> u32 {
        { self.gid }.to_native()
    }

    pub fn links(&self) -> u32 {
        { self.links }.to_native()
    }

    pub fn size(&self) -> u64 {
        { self.size }.to_native()
    }

    pub fn ctime(&self) -> (u64, u32) {
        ({ self.ctime }.to_native(), { self.ctime_nsec }.to_native())
    }

    pub fn mtime(&self) -> (u64, u32) {
        ({ self.mtime }.to_native(), { self.mtime_nsec }.to_native())
    }

    pub fn atime(&self) -> (u64, u32) {
        ({ self.atime }.to_native(), { self.atime_nsec }.to_native())
    }

    pub fn set_mode(&mut self, mode: u16) {
        self.mode = mode.into();
    }

    pub fn set_uid(&mut self, uid: u32) {
        self.uid = uid.into();
    }

    pub fn set_gid(&mut self, gid: u32) {
        self.gid = gid.into();
    }

    pub fn set_links(&mut self, links: u32) {
        self.links = links.into();
    }

    pub fn set_size(&mut self, size: u64) {
        self.size = size.into();
    }

    pub fn set_mtime(&mut self, mtime: u64, mtime_nsec: u32) {
        self.mtime = mtime.into();
        self.mtime_nsec = mtime_nsec.into();
    }

    pub fn set_atime(&mut self, atime: u64, atime_nsec: u32) {
        self.atime = atime.into();
        self.atime_nsec = atime_nsec.into();
    }

    pub fn is_dir(&self) -> bool {
        self.mode() & Self::MODE_TYPE == Self::MODE_DIR
    }

    pub fn is_file(&self) -> bool {
        self.mode() & Self::MODE_TYPE == Self::MODE_FILE
    }

    pub fn is_symlink(&self) -> bool {
        self.mode() & Self::MODE_TYPE == Self::MODE_SYMLINK
    }

    /// Tests if UID is the owner of that file, only true when uid=0 or when the UID stored in metadata is equal to the UID you supply
    pub fn owner(&self, uid: u32) -> bool {
        uid == 0 || self.uid() == uid
    }

    /// Tests if the current user has enough permissions to view the file, op is the operation,
    /// like read and write, these modes are MODE_EXEC, MODE_READ, and MODE_WRITE
    pub fn permission(&self, uid: u32, gid: u32, op: u16) -> bool {
        let mut perm = self.mode() & 0o7;
        if self.uid() == uid {
            // If self.mode is 101100110, >> 6 would be 000000101
            // 0o7 is octal for 111, or, when expanded to 9 digits is 000000111
            perm |= (self.mode() >> 6) & 0o7;
            // Since we erased the GID and OTHER bits when >>6'ing, |= will keep those bits in place.
        }
        if self.gid() == gid || gid == 0 {
            perm |= (self.mode() >> 3) & 0o7;
        }
        if uid == 0 {
            //set the `other` bits to 111
            perm |= 0o7;
        }
        perm & op == op
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mode = self.mode;
        let uid = self.uid;
        let gid = self.gid;
        let links = self.links;
        let size = self.size;
        let ctime = self.ctime;
        let ctime_nsec = self.ctime_nsec;
        let mtime = self.mtime;
        let mtime_nsec = self.mtime_nsec;
        let atime = self.atime;
        let atime_nsec = self.atime_nsec;
        f.debug_struct("Node")
            .field("mode", &mode)
            .field("uid", &uid)
            .field("gid", &gid)
            .field("links", &links)
            .field("size", &size)
            .field("ctime", &ctime)
            .field("ctime_nsec", &ctime_nsec)
            .field("mtime", &mtime)
            .field("mtime_nsec", &mtime_nsec)
            .field("atime", &atime)
            .field("atime_nsec", &atime_nsec)
            //TODO: level0/1/2/3
            .finish()
    }
}

impl ops::Deref for Node {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self as *const Node as *const u8, mem::size_of::<Node>())
                as &[u8]
        }
    }
}

impl ops::DerefMut for Node {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self as *mut Node as *mut u8, mem::size_of::<Node>())
                as &mut [u8]
        }
    }
}

#[test]
fn node_size_test() {
    assert_eq!(mem::size_of::<Node>(), crate::BLOCK_SIZE as usize);
}
