use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
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

pub struct DiskFile {
    pub file: File,
}

impl DiskFile {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<DiskFile> {
        let file = try_disk!(OpenOptions::new().read(true).write(true).open(path));
        Ok(DiskFile { file })
    }

    pub fn create<P: AsRef<Path>>(path: P, size: u64) -> Result<DiskFile> {
        let file = try_disk!(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path));
        try_disk!(file.set_len(size));
        Ok(DiskFile { file })
    }
}

impl Disk for DiskFile {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        try_disk!(self.file.seek(SeekFrom::Start(block * BLOCK_SIZE)));
        let count = try_disk!(self.file.read(buffer));
        Ok(count)
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        try_disk!(self.file.seek(SeekFrom::Start(block * BLOCK_SIZE)));
        let count = try_disk!(self.file.write(buffer));
        Ok(count)
    }

    fn size(&mut self) -> Result<u64> {
        let size = try_disk!(self.file.seek(SeekFrom::End(0)));
        Ok(size)
    }
}
