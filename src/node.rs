use core::{fmt, mem, ops, slice};
use endian_num::Le;

use crate::{BlockLevel, BlockList, BlockPtr, BlockTrait, RecordRaw, BLOCK_SIZE, RECORD_LEVEL};

/// An index into a [`Node`]'s block table.
pub enum NodeLevel {
    L0(usize),
    L1(usize, usize),
    L2(usize, usize, usize),
    L3(usize, usize, usize, usize),
    L4(usize, usize, usize, usize, usize),
}

impl NodeLevel {
    // Warning: this uses constant record offsets, make sure to sync with Node

    /// Return the [`NodeLevel`] of the record with the given index.
    /// - the first 128 are level 0,
    /// - the next 64*256 are level 1,
    /// - ...and so on.
    pub fn new(mut record_offset: u64) -> Option<Self> {
        // 1 << 8 = 256, this is the number of entries in a BlockList
        const SHIFT: u64 = 8;
        const NUM: u64 = 1 << SHIFT;
        const MASK: u64 = NUM - 1;

        const L0: u64 = 128;
        if record_offset < L0 {
            return Some(Self::L0((record_offset & MASK) as usize));
        } else {
            record_offset -= L0;
        }

        const L1: u64 = 64 * NUM;
        if record_offset < L1 {
            return Some(Self::L1(
                ((record_offset >> SHIFT) & MASK) as usize,
                (record_offset & MASK) as usize,
            ));
        } else {
            record_offset -= L1;
        }

        const L2: u64 = 32 * NUM * NUM;
        if record_offset < L2 {
            return Some(Self::L2(
                ((record_offset >> (2 * SHIFT)) & MASK) as usize,
                ((record_offset >> SHIFT) & MASK) as usize,
                (record_offset & MASK) as usize,
            ));
        } else {
            record_offset -= L2;
        }

        const L3: u64 = 16 * NUM * NUM * NUM;
        if record_offset < L3 {
            return Some(Self::L3(
                ((record_offset >> (3 * SHIFT)) & MASK) as usize,
                ((record_offset >> (2 * SHIFT)) & MASK) as usize,
                ((record_offset >> SHIFT) & MASK) as usize,
                (record_offset & MASK) as usize,
            ));
        } else {
            record_offset -= L3;
        }

        const L4: u64 = 12 * NUM * NUM * NUM * NUM;
        if record_offset < L4 {
            Some(Self::L4(
                ((record_offset >> (4 * SHIFT)) & MASK) as usize,
                ((record_offset >> (3 * SHIFT)) & MASK) as usize,
                ((record_offset >> (2 * SHIFT)) & MASK) as usize,
                ((record_offset >> SHIFT) & MASK) as usize,
                (record_offset & MASK) as usize,
            ))
        } else {
            None
        }
    }
}

type BlockListL1 = BlockList<RecordRaw>;
type BlockListL2 = BlockList<BlockListL1>;
type BlockListL3 = BlockList<BlockListL2>;
type BlockListL4 = BlockList<BlockListL3>;

/// A file/folder node
#[repr(C, packed)]
pub struct Node {
    /// This node's type & permissions.
    /// - four most significant bits are the node's type
    /// - next four bits are permissions for the node's user
    /// - next four bits are permissions for the node's group
    /// - four least significant bits are permissions for everyone else
    pub mode: Le<u16>,

    /// The uid that owns this file
    pub uid: Le<u32>,

    /// The gid that owns this file
    pub gid: Le<u32>,

    /// The number of links to this file
    /// (directory entries, symlinks, etc)
    pub links: Le<u32>,

    /// The length of this file, in bytes
    pub size: Le<u64>,
    /// The disk usage of this file, in blocks
    pub blocks: Le<u64>,

    /// Creation time
    pub ctime: Le<u64>,
    pub ctime_nsec: Le<u32>,

    /// Modification time
    pub mtime: Le<u64>,
    pub mtime_nsec: Le<u32>,

    /// Access time
    pub atime: Le<u64>,
    pub atime_nsec: Le<u32>,

    /// Record level
    pub record_level: Le<u32>,

    pub padding: [u8; BLOCK_SIZE as usize - 4038],

    /// The first 128 blocks of this file.
    ///
    /// Total size: 128 * RECORD_SIZE (16 MiB, 128 KiB each)
    pub level0: [BlockPtr<RecordRaw>; 128],

    /// The next 64 * 256 blocks of this file,
    /// stored behind 64 level one tables.
    ///
    /// Total size: 64 * 256 * RECORD_SIZE (2 GiB, 32 MiB each)
    pub level1: [BlockPtr<BlockListL1>; 64],

    /// The next 32 * 256 * 256 blocks of this file,
    /// stored behind 32 level two tables.
    /// Each level two table points to 256 level one tables.
    ///
    /// Total size: 32 * 256 * 256 * RECORD_SIZE (256 GiB, 8 GiB each)
    pub level2: [BlockPtr<BlockListL2>; 32],

    /// The next 16 * 256 * 256 * 256 blocks of this file,
    /// stored behind 16 level three tables.
    ///
    /// Total size: 16 * 256 * 256 * 256 * RECORD_SIZE (32 TiB, 2 TiB each)
    pub level3: [BlockPtr<BlockListL3>; 16],

    /// The next 8 * 256 * 256 * 256 * 256 blocks of this file,
    /// stored behind 8 level four tables.
    ///
    /// Total size: 8 * 256 * 256 * 256 * 256 * RECORD_SIZE (4 PiB, 512 TiB each)
    pub level4: [BlockPtr<BlockListL4>; 8],
}

unsafe impl BlockTrait for Node {
    fn empty(level: BlockLevel) -> Option<Self> {
        if level.0 == 0 {
            Some(Self::default())
        } else {
            None
        }
    }
}

impl Default for Node {
    fn default() -> Self {
        Self {
            mode: 0.into(),
            uid: 0.into(),
            gid: 0.into(),
            links: 0.into(),
            size: 0.into(),
            // Node counts as a block.
            //TODO: track all the blocks in indirect levels
            blocks: 1.into(),
            ctime: 0.into(),
            ctime_nsec: 0.into(),
            mtime: 0.into(),
            mtime_nsec: 0.into(),
            atime: 0.into(),
            atime_nsec: 0.into(),
            record_level: 0.into(),
            padding: [0; BLOCK_SIZE as usize - 4038],
            level0: [BlockPtr::default(); 128],
            level1: [BlockPtr::default(); 64],
            level2: [BlockPtr::default(); 32],
            level3: [BlockPtr::default(); 16],
            level4: [BlockPtr::default(); 8],
        }
    }
}

impl Node {
    pub const MODE_TYPE: u16 = 0xF000;
    pub const MODE_FILE: u16 = 0x8000;
    pub const MODE_DIR: u16 = 0x4000;
    pub const MODE_SYMLINK: u16 = 0xA000;
    pub const MODE_SOCK: u16 = 0xC000;

    /// Mask for node permission bits
    pub const MODE_PERM: u16 = 0x0FFF;
    pub const MODE_EXEC: u16 = 0o1;
    pub const MODE_WRITE: u16 = 0o2;
    pub const MODE_READ: u16 = 0o4;

    /// Create a new, empty node with the given metadata
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
            record_level: if mode & Self::MODE_TYPE == Self::MODE_FILE {
                // Files take on record level
                RECORD_LEVEL as u32
            } else {
                // Folders do not
                0
            }
            .into(),
            ..Default::default()
        }
    }

    /// This node's type & permissions.
    /// - four most significant bits are the node's type
    /// - next four bits are permissions for the node's user
    /// - next four bits are permissions for the node's group
    /// - four least significant bits are permissions for everyone else
    pub fn mode(&self) -> u16 {
        self.mode.to_ne()
    }

    /// The uid that owns this file
    pub fn uid(&self) -> u32 {
        self.uid.to_ne()
    }

    /// The gid that owns this file
    pub fn gid(&self) -> u32 {
        self.gid.to_ne()
    }

    /// The number of links to this file
    /// (directory entries, symlinks, etc)
    pub fn links(&self) -> u32 {
        self.links.to_ne()
    }

    /// The length of this file, in bytes.
    pub fn size(&self) -> u64 {
        self.size.to_ne()
    }

    /// The disk usage of this file, in blocks.
    pub fn blocks(&self) -> u64 {
        self.blocks.to_ne()
    }

    pub fn ctime(&self) -> (u64, u32) {
        (self.ctime.to_ne(), self.ctime_nsec.to_ne())
    }

    pub fn mtime(&self) -> (u64, u32) {
        (self.mtime.to_ne(), self.mtime_nsec.to_ne())
    }

    pub fn atime(&self) -> (u64, u32) {
        (self.atime.to_ne(), self.atime_nsec.to_ne())
    }

    pub fn record_level(&self) -> BlockLevel {
        BlockLevel(self.record_level.to_ne() as usize)
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

    pub fn set_blocks(&mut self, blocks: u64) {
        self.blocks = blocks.into();
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

    pub fn is_sock(&self) -> bool {
        self.mode() & Self::MODE_SOCK == Self::MODE_SOCK
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

#[cfg(kani)]
#[kani::proof]
fn check_node_level() {
    let offset = kani::any();
    NodeLevel::new(offset);
}

#[cfg(kani)]
#[kani::proof]
fn check_node_perms() {
    let mode = 0o750;

    let uid = kani::any();
    let gid = kani::any();

    let ctime = kani::any();
    let ctime_nsec = kani::any();

    let node = Node::new(mode, uid, gid, ctime, ctime_nsec);

    let root_uid = 0;
    let root_gid = 0;

    let other_uid = kani::any();
    kani::assume(other_uid != uid);
    kani::assume(other_uid != root_uid);
    let other_gid = kani::any();
    kani::assume(other_gid != gid);
    kani::assume(other_gid != root_gid);

    assert!(node.owner(uid));
    assert!(node.permission(uid, gid, 0o7));
    assert!(node.permission(uid, gid, 0o5));
    assert!(node.permission(uid, other_gid, 0o7));
    assert!(node.permission(uid, other_gid, 0o5));
    assert!(!node.permission(other_uid, gid, 0o7));
    assert!(node.permission(other_uid, gid, 0o5));

    assert!(node.owner(root_uid));
    assert!(node.permission(root_uid, root_gid, 0o7));
    assert!(node.permission(root_uid, root_gid, 0o5));
    assert!(node.permission(root_uid, other_gid, 0o7));
    assert!(node.permission(root_uid, other_gid, 0o5));
    assert!(!node.permission(other_uid, root_gid, 0o7));
    assert!(node.permission(other_uid, root_gid, 0o5));

    assert!(!node.owner(other_uid));
    assert!(!node.permission(other_uid, other_gid, 0o7));
    assert!(!node.permission(other_uid, other_gid, 0o5));
}
