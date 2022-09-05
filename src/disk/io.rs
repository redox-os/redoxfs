use std::io::{Read, Seek, SeekFrom, Write};
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

pub struct DiskIo<T>(pub T);

impl<T: Read + Write + Seek> Disk for DiskIo<T> {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        try_disk!(self.0.seek(SeekFrom::Start(block * BLOCK_SIZE)));
        let count = try_disk!(self.0.read(buffer));
        Ok(count)
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        try_disk!(self.0.seek(SeekFrom::Start(block * BLOCK_SIZE)));
        let count = try_disk!(self.0.write(buffer));
        Ok(count)
    }

    fn size(&mut self) -> Result<u64> {
        let size = try_disk!(self.0.seek(SeekFrom::End(0)));
        Ok(size)
    }
}
