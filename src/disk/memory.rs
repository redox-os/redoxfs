use syscall::error::{Error, Result, EIO};

use crate::disk::Disk;
use crate::BLOCK_SIZE;

pub struct DiskMemory {
    data: Vec<u8>,
}

impl DiskMemory {
    pub fn new(size: u64) -> DiskMemory {
        DiskMemory {
            data: vec![0; size as usize],
        }
    }
}

impl Disk for DiskMemory {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        let offset = (block * BLOCK_SIZE) as usize;
        let end = offset + buffer.len();
        if end > self.data.len() {
            return Err(Error::new(EIO));
        }
        buffer.copy_from_slice(&self.data[offset..end]);
        Ok(buffer.len())
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        let offset = (block * BLOCK_SIZE) as usize;
        let end = offset + buffer.len();
        if end > self.data.len() {
            return Err(Error::new(EIO));
        }
        self.data[offset..end].copy_from_slice(buffer);
        Ok(buffer.len())
    }

    fn size(&mut self) -> Result<u64> {
        Ok(self.data.len() as u64)
    }
}
