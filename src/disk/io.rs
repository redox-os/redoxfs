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
pub struct DiskIo<T> {
    io: Mutex<T>,
    size: u64,
}

impl<T: Seek> DiskIo<T> {
    fn new(mut t: T) -> Result<Self> {
        let sz = try_disk!(t.seek(SeekFrom::End(0)));
        Ok(Self {
            io: Mutex::new(t),
            size: sz,
        })
    }
}

impl<T: Read + Write + Seek> Disk for DiskIo<T> {
    async unsafe fn read_at(&self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        let mut io = self.io.lock().await;
        try_disk!(io.seek(SeekFrom::Start(block * BLOCK_SIZE)));
        let count = try_disk!(io.read(buffer));
        Ok(count)
    }

    async unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        let mut io = self.io.lock().await;
        try_disk!(io.seek(SeekFrom::Start(block * BLOCK_SIZE)));
        let count = try_disk!(io.write(buffer));
        Ok(count)
    }

    fn size(&mut self) -> Result<u64> {
        Ok(self.size)
    }
}
