use aes::Aes128;
use alloc::collections::VecDeque;
use syscall::error::{Error, Result, EKEYREJECTED, ENOENT, ENOKEY};
use xts_mode::{get_tweak_default, Xts128};

#[cfg(feature = "std")]
use crate::{AllocEntry, AllocList, BlockData, BlockTrait, Key, KeySlot, Node, Salt, TreeList};
use crate::{Allocator, BlockAddr, BlockLevel, Disk, Header, Transaction, BLOCK_SIZE, HEADER_RING};

/// A file system
pub struct FileSystem<D: Disk> {
    //TODO: make private
    pub disk: D,
    //TODO: make private
    pub block: u64,
    //TODO: make private
    pub header: Header,
    pub(crate) allocator: Allocator,
    pub(crate) cipher_opt: Option<Xts128<Aes128>>,
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

            let cipher_opt = match password_opt {
                Some(password) => {
                    if !header.encrypted() {
                        // Header not encrypted but password provided
                        return Err(Error::new(EKEYREJECTED));
                    }
                    match header.cipher(password) {
                        Some(cipher) => Some(cipher),
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
                cipher_opt,
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
        let block_offset = (reserved.len() as u64).div_ceil(BLOCK_SIZE);

        if size < (block_offset + HEADER_RING + 4) * BLOCK_SIZE {
            return Err(Error::new(syscall::error::ENOSPC));
        }

        // Fill reserved data, pad with zeroes
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

        let cipher_opt = match password_opt {
            Some(password) => {
                //TODO: handle errors
                header.key_slots[0] = KeySlot::new(
                    password,
                    Salt::new().unwrap(),
                    (Key::new().unwrap(), Key::new().unwrap()),
                )
                .unwrap();
                Some(header.key_slots[0].cipher(password).unwrap())
            }
            None => None,
        };

        let mut fs = FileSystem {
            disk,
            block: block_offset,
            header,
            allocator: Allocator::default(),
            cipher_opt,
        };

        // Write header generation zero
        let count = unsafe { fs.disk.write_at(fs.block, &fs.header)? };
        if count != core::mem::size_of_val(&fs.header) {
            // Wrote wrong number of bytes
            #[cfg(feature = "log")]
            log::error!("CREATE: WRONG NUMBER OF BYTES");
            return Err(Error::new(syscall::error::EIO));
        }

        // Set tree and alloc pointers and write header generation one
        fs.tx(|tx| unsafe {
            let tree = BlockData::new(
                BlockAddr::new(HEADER_RING + 1, BlockLevel::default()),
                TreeList::empty(BlockLevel::default()).unwrap(),
            );

            let mut alloc = BlockData::new(
                BlockAddr::new(HEADER_RING + 2, BlockLevel::default()),
                AllocList::empty(BlockLevel::default()).unwrap(),
            );

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
                BlockAddr::new(HEADER_RING + 3, BlockLevel::default()),
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
    }

    /// start a filesystem transaction, required for making any changes
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
    /// Unsafe, it must only be called when opening the filesystem
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
                let index = entry.index();
                let count = entry.count();
                if count < 0 {
                    for i in 0..-count {
                        //TODO: replace assert with error?
                        let addr = BlockAddr::new(index + i as u64, BlockLevel::default());
                        assert_eq!(self.allocator.allocate_exact(addr), Some(addr));
                    }
                } else {
                    for i in 0..count {
                        let addr = BlockAddr::new(index + i as u64, BlockLevel::default());
                        self.allocator.deallocate(addr);
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) fn decrypt(&mut self, data: &mut [u8], addr: BlockAddr) -> bool {
        if let Some(ref cipher) = self.cipher_opt {
            cipher.decrypt_area(
                data,
                BLOCK_SIZE as usize,
                addr.index().into(),
                get_tweak_default,
            );
            true
        } else {
            // Do nothing if encryption is disabled
            false
        }
    }

    pub(crate) fn encrypt(&mut self, data: &mut [u8], addr: BlockAddr) -> bool {
        if let Some(ref cipher) = self.cipher_opt {
            cipher.encrypt_area(
                data,
                BLOCK_SIZE as usize,
                addr.index().into(),
                get_tweak_default,
            );
            true
        } else {
            // Do nothing if encryption is disabled
            false
        }
    }
}
