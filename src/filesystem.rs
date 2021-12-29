use aes::{Aes128, BlockDecrypt, BlockEncrypt};
use alloc::{collections::VecDeque, vec::Vec};
use syscall::error::{Error, Result, EKEYREJECTED, ENOENT, ENOKEY, ENOSPC};

use crate::{
    AllocEntry, AllocList, Allocator, BlockData, Disk, Header, Key, KeySlot, Node, Salt,
    Transaction, TreeList, BLOCK_SIZE, HEADER_RING,
};

/// A file system
pub struct FileSystem<D: Disk> {
    //TODO: make private
    pub disk: D,
    //TODO: make private
    pub block: u64,
    //TODO: make private
    pub header: Header,
    pub(crate) allocator: Allocator,
    pub(crate) aes_opt: Option<Aes128>,
    aes_blocks: Vec<aes::Block>,
}

impl<D: Disk> FileSystem<D> {
    /// Open a file system on a disk
    pub fn open(
        mut disk: D,
        password_opt: Option<&[u8]>,
        block_opt: Option<u64>,
        squash: bool,
    ) -> Result<Self> {
        for ring_block in block_opt.map_or(0..65536, |x| x..x + 1) {
            let mut header = Header::default();
            unsafe { disk.read_at(ring_block, &mut header)? };

            // Skip invalid headers
            if !header.valid() {
                continue;
            }

            let block = ring_block - (header.generation() % HEADER_RING);
            for i in 0..HEADER_RING {
                let mut other_header = Header::default();
                unsafe { disk.read_at(block + i, &mut other_header)? };

                // Skip invalid headers
                if !other_header.valid() {
                    continue;
                }

                // If this is a newer header, use it
                if other_header.generation() > header.generation() {
                    header = other_header;
                }
            }

            let aes_opt = match password_opt {
                Some(password) => {
                    if !header.encrypted() {
                        // Header not encrypted but password provided
                        return Err(Error::new(EKEYREJECTED));
                    }
                    match header.aes(password) {
                        Some(aes) => Some(aes),
                        None => {
                            // Header encrypted with a different password
                            return Err(Error::new(ENOKEY));
                        }
                    }
                }
                None => {
                    if header.encrypted() {
                        // Header encrypted but no password provided
                        return Err(Error::new(ENOKEY));
                    }
                    None
                }
            };

            let mut fs = FileSystem {
                disk,
                block,
                header,
                allocator: Allocator::default(),
                aes_opt,
                aes_blocks: Vec::with_capacity(BLOCK_SIZE as usize / aes::BLOCK_SIZE),
            };

            unsafe { fs.reset_allocator()? };

            // Squash allocations and sync
            Transaction::new(&mut fs).commit(squash)?;

            return Ok(fs);
        }

        Err(Error::new(ENOENT))
    }

    /// Create a file system on a disk
    #[cfg(feature = "std")]
    pub fn create(
        disk: D,
        password_opt: Option<&[u8]>,
        ctime: u64,
        ctime_nsec: u32,
    ) -> Result<Self> {
        Self::create_reserved(disk, password_opt, &[], ctime, ctime_nsec)
    }

    /// Create a file system on a disk, with reserved data at the beginning
    /// Reserved data will be zero padded up to the nearest block
    /// We need to pass ctime and ctime_nsec in order to initialize the unix timestamps
    #[cfg(feature = "std")]
    pub fn create_reserved(
        mut disk: D,
        password_opt: Option<&[u8]>,
        reserved: &[u8],
        ctime: u64,
        ctime_nsec: u32,
    ) -> Result<Self> {
        let size = disk.size()?;
        let block_offset = (reserved.len() as u64 + BLOCK_SIZE - 1) / BLOCK_SIZE;

        if size >= (block_offset + HEADER_RING + 4) * BLOCK_SIZE {
            for block in 0..block_offset as usize {
                let mut data = [0; BLOCK_SIZE as usize];

                let mut i = 0;
                while i < data.len() && block * BLOCK_SIZE as usize + i < reserved.len() {
                    data[i] = reserved[block * BLOCK_SIZE as usize + i];
                    i += 1;
                }

                unsafe {
                    disk.write_at(block as u64, &data)?;
                }
            }

            let mut header = Header::new(size);

            let aes_opt = match password_opt {
                Some(password) => {
                    //TODO: handle errors
                    header.key_slots[0] =
                        KeySlot::new(password, Salt::new().unwrap(), Key::new().unwrap()).unwrap();
                    Some(header.key_slots[0].key(password).unwrap().into_aes())
                }
                None => None,
            };

            let mut fs = FileSystem {
                disk,
                block: block_offset,
                header,
                allocator: Allocator::default(),
                aes_opt,
                aes_blocks: Vec::with_capacity(BLOCK_SIZE as usize / aes::BLOCK_SIZE),
            };

            fs.tx(|tx| unsafe {
                let tree = BlockData::new(HEADER_RING + 1, TreeList::default());

                let mut alloc = BlockData::new(HEADER_RING + 2, AllocList::default());
                let alloc_free = size / BLOCK_SIZE - (block_offset + HEADER_RING + 4);
                alloc.data_mut().entries[0] = AllocEntry::new(HEADER_RING + 4, alloc_free as i64);

                tx.header.tree = tx.write_block(tree)?;
                tx.header.alloc = tx.write_block(alloc)?;
                tx.header_changed = true;

                Ok(())
            })?;

            unsafe {
                fs.reset_allocator()?;
            }

            fs.tx(|tx| unsafe {
                let mut root = BlockData::new(
                    HEADER_RING + 3,
                    Node::new(Node::MODE_DIR | 0o755, 0, 0, ctime, ctime_nsec),
                );
                root.data_mut().set_links(1);
                let root_ptr = tx.write_block(root)?;
                assert_eq!(tx.insert_tree(root_ptr)?.id(), 1);
                Ok(())
            })?;

            // Make sure everything is synced and squash allocations
            Transaction::new(&mut fs).commit(true)?;

            Ok(fs)
        } else {
            Err(Error::new(ENOSPC))
        }
    }

    /// Start a filesystem transaction, required for making any changes
    pub fn tx<F: FnOnce(&mut Transaction<D>) -> Result<T>, T>(&mut self, f: F) -> Result<T> {
        let mut tx = Transaction::new(self);
        let t = f(&mut tx)?;
        tx.commit(false)?;
        Ok(t)
    }

    pub fn allocator(&self) -> &Allocator {
        &self.allocator
    }

    /// Reset allocator to state stored on disk
    ///
    /// # Safety
    /// Unsafe, it must only be called when openning the filesystem
    unsafe fn reset_allocator(&mut self) -> Result<()> {
        self.allocator = Allocator::default();

        // To avoid having to update all prior alloc blocks, there is only a previous pointer
        // This means we need to roll back all allocations. Currently we do this by reading the
        // alloc log into a buffer to reverse it.
        let mut allocs = VecDeque::new();
        self.tx(|tx| {
            let mut alloc_ptr = tx.header.alloc;
            while !alloc_ptr.is_null() {
                let alloc = tx.read_block(alloc_ptr)?;
                alloc_ptr = alloc.data().prev;
                allocs.push_front(alloc);
            }
            Ok(())
        })?;

        for alloc in allocs {
            for entry in alloc.data().entries.iter() {
                let addr = entry.addr();
                let count = entry.count();
                if count < 0 {
                    for i in 0..-count {
                        //TODO: replace assert with error?
                        assert_eq!(
                            self.allocator.allocate_exact(addr + i as u64),
                            Some(addr + i as u64)
                        );
                    }
                } else {
                    for i in 0..count {
                        self.allocator.deallocate(addr + i as u64);
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) fn decrypt(&mut self, data: &mut [u8]) -> bool {
        if let Some(ref aes) = self.aes_opt {
            assert_eq!(data.len() % aes::BLOCK_SIZE, 0);

            self.aes_blocks.clear();
            for i in 0..data.len() / aes::BLOCK_SIZE {
                self.aes_blocks.push(aes::Block::clone_from_slice(
                    &data[i * aes::BLOCK_SIZE..(i + 1) * aes::BLOCK_SIZE],
                ));
            }

            aes.decrypt_blocks(&mut self.aes_blocks);

            for i in 0..data.len() / aes::BLOCK_SIZE {
                data[i * aes::BLOCK_SIZE..(i + 1) * aes::BLOCK_SIZE]
                    .copy_from_slice(&self.aes_blocks[i]);
            }
            self.aes_blocks.clear();

            true
        } else {
            false
        }
    }

    pub(crate) fn encrypt(&mut self, data: &mut [u8]) -> bool {
        if let Some(ref aes) = self.aes_opt {
            assert_eq!(data.len() % aes::BLOCK_SIZE, 0);

            self.aes_blocks.clear();
            for i in 0..data.len() / aes::BLOCK_SIZE {
                self.aes_blocks.push(aes::Block::clone_from_slice(
                    &data[i * aes::BLOCK_SIZE..(i + 1) * aes::BLOCK_SIZE],
                ));
            }

            aes.encrypt_blocks(&mut self.aes_blocks);

            for i in 0..data.len() / aes::BLOCK_SIZE {
                data[i * aes::BLOCK_SIZE..(i + 1) * aes::BLOCK_SIZE]
                    .copy_from_slice(&self.aes_blocks[i]);
            }
            self.aes_blocks.clear();

            true
        } else {
            false
        }
    }
}
