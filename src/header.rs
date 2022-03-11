use core::ops::{Deref, DerefMut};
use core::{fmt, mem, slice};
use redox_simple_endian::*;

use aes::{Aes128, BlockDecrypt, BlockEncrypt};
use uuid::Uuid;

use crate::{AllocList, BlockPtr, KeySlot, Tree, BLOCK_SIZE, SIGNATURE, VERSION};

pub const HEADER_RING: u64 = 256;

/// The header of the filesystem
#[derive(Clone, Copy)]
#[repr(packed)]
pub struct Header {
    /// Signature, should be SIGNATURE
    pub signature: [u8; 8],
    /// Version, should be VERSION
    pub version: u64le,
    /// Disk ID, a 128-bit unique identifier
    pub uuid: [u8; 16],
    /// Disk size, in number of BLOCK_SIZE sectors
    pub size: u64le,
    /// Generation of header
    pub generation: u64le,
    /// Block of first tree node
    pub tree: BlockPtr<Tree>,
    /// Block of last alloc node
    pub alloc: BlockPtr<AllocList>,
    /// Key slots
    pub key_slots: [KeySlot; 64],
    /// Padding
    pub padding: [u8; BLOCK_SIZE as usize - 2152],
    /// encrypted hash of header data without hash, set to hash and padded if disk is not encrypted
    pub encrypted_hash: [u8; 16],
    /// hash of header data without hash
    pub hash: u64le,
}

impl Header {
    #[cfg(feature = "std")]
    pub fn new(size: u64) -> Header {
        let uuid = Uuid::new_v4();
        let mut header = Header {
            signature: *SIGNATURE,
            version: VERSION.into(),
            uuid: *uuid.as_bytes(),
            size: size.into(),
            ..Default::default()
        };
        header.update_hash(None);
        header
    }

    pub fn valid(&self) -> bool {
        if &self.signature != SIGNATURE {
            // Signature does not match
            return false;
        }

        if { self.version }.to_native() != VERSION {
            // Version does not match
            return false;
        }

        if { self.hash }.to_native() != self.create_hash() {
            // Hash does not match
            return false;
        }

        // All tests passed, header is valid
        true
    }

    pub fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    pub fn size(&self) -> u64 {
        { self.size }.to_native()
    }

    pub fn generation(&self) -> u64 {
        { self.generation }.to_native()
    }

    fn create_hash(&self) -> u64 {
        // Calculate part of header to hash (everything before the hashes)
        let end = mem::size_of_val(self)
            - mem::size_of_val(&{ self.hash })
            - mem::size_of_val(&{ self.encrypted_hash });
        seahash::hash(&self[..end])
    }

    fn create_encrypted_hash(&self, aes_opt: Option<&Aes128>) -> [u8; 16] {
        let mut encrypted_hash = [0; 16];
        for (i, b) in { self.hash }.to_native().to_le_bytes().iter().enumerate() {
            encrypted_hash[i] = *b;
        }
        if let Some(aes) = aes_opt {
            let mut block = aes::Block::from(encrypted_hash);
            aes.encrypt_block(&mut block);
            encrypted_hash = block.into();
        }
        encrypted_hash
    }

    pub fn encrypted(&self) -> bool {
        (self.encrypted_hash) != self.create_encrypted_hash(None)
    }

    pub fn aes(&self, password: &[u8]) -> Option<Aes128> {
        let hash = self.create_encrypted_hash(None);
        for slot in self.key_slots.iter() {
            //TODO: handle errors
            let aes = slot.key(password).unwrap().into_aes();
            let mut block = aes::Block::from(self.encrypted_hash);
            aes.decrypt_block(&mut block);
            if block == aes::Block::from(hash) {
                return Some(aes);
            }
        }
        None
    }
    fn update_hash(&mut self, aes_opt: Option<&Aes128>) {
        self.hash = self.create_hash().into();
        // Make sure to do this second, it relies on the hash being up to date
        self.encrypted_hash = self.create_encrypted_hash(aes_opt);
    }

    pub fn update(&mut self, aes_opt: Option<&Aes128>) -> u64 {
        let mut generation = self.generation();
        generation += 1;
        self.generation = generation.into();
        self.update_hash(aes_opt);
        generation
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            signature: [0; 8],
            version: 0.into(),
            uuid: [0; 16],
            size: 0.into(),
            generation: 0.into(),
            tree: BlockPtr::<Tree>::default(),
            alloc: BlockPtr::<AllocList>::default(),
            key_slots: [KeySlot::default(); 64],
            padding: [0; BLOCK_SIZE as usize - 2152],
            encrypted_hash: [0; 16],
            hash: 0.into(),
        }
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let signature = self.signature;
        let version = self.version;
        let uuid = self.uuid;
        let size = self.size;
        let generation = self.generation;
        let tree = self.tree;
        let alloc = self.alloc;
        let hash = self.hash;
        f.debug_struct("Header")
            .field("signature", &signature)
            .field("version", &version)
            .field("uuid", &uuid)
            .field("size", &size)
            .field("generation", &generation)
            .field("tree", &tree)
            .field("alloc", &alloc)
            .field("hash", &hash)
            .finish()
    }
}

impl Deref for Header {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self as *const Header as *const u8, mem::size_of::<Header>())
                as &[u8]
        }
    }
}

impl DerefMut for Header {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self as *mut Header as *mut u8, mem::size_of::<Header>())
                as &mut [u8]
        }
    }
}

#[test]
fn header_not_valid_test() {
    assert_eq!(Header::default().valid(), false);
}

#[test]
fn header_size_test() {
    assert_eq!(mem::size_of::<Header>(), BLOCK_SIZE as usize);
}

#[test]
fn header_hash_test() {
    let mut header = Header::default();
    assert_eq!(header.create_hash(), 0xe81ffcb86026ff96);
    header.update_hash(None);
    assert_eq!({ header.hash }.to_native(), 0xe81ffcb86026ff96);
    assert_eq!(
        header.encrypted_hash,
        [0x96, 0xff, 0x26, 0x60, 0xb8, 0xfc, 0x1f, 0xe8, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[cfg(feature = "std")]
#[test]
fn header_valid_test() {
    assert_eq!(Header::new(0).valid(), true);
}
