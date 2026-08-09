use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;
use syscall::error::{Error, Result, EIO};

use crate::disk::Disk;
use crate::BLOCK_SIZE;

macro_rules! try_disk {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => {
                eprintln!("Disk I/O Error: {}", err);
                return Err(Error::new(EIO));
            }
        }
    };
}

pub struct DiskSparse {
    pub file: File,
    pub max_size: u64,
}

impl DiskSparse {
    pub fn create<P: AsRef<Path>>(path: P, max_size: u64) -> Result<DiskSparse> {
        let file = try_disk!(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path));
        Ok(DiskSparse { file, max_size })
    }
}

impl Disk for DiskSparse {
    async unsafe fn read_at(&self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        Ok(try_disk!(self.file.read_at(buffer, block * BLOCK_SIZE)))
    }

    async unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        Ok(try_disk!(self.file.write_at(buffer, block * BLOCK_SIZE)))
    }

    fn size(&mut self) -> Result<u64> {
        Ok(self.max_size)
    }
}
