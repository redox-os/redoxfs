use async_lock::Mutex;
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

// The lack of ReadAt and WriteAt traits forces us to serialize
// all I/O through this type.
pub struct DiskIo<T>(pub Mutex<T>);

impl<T: Read + Write + Seek> Disk for DiskIo<T> {
    async unsafe fn read_at(&self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        let mut io = self.0.lock().await;
        try_disk!(io.seek(SeekFrom::Start(block * BLOCK_SIZE)));
        let count = try_disk!(io.read(buffer));
        Ok(count)
    }

    async unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        let io = self.0.get_mut();
        try_disk!(io.seek(SeekFrom::Start(block * BLOCK_SIZE)));
        let count = try_disk!(io.write(buffer));
        Ok(count)
    }

    fn size(&mut self) -> Result<u64> {
        Ok(try_disk!(self.0.get_mut().seek(SeekFrom::End(0))))
    }
}
