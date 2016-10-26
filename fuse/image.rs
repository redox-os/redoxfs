use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};

use redoxfs::Disk;
use syscall::error::{Error, Result, EIO};

macro_rules! try_disk {
    ($expr:expr) => (match $expr {
        Ok(val) => val,
        Err(err) => {
            println!("Disk I/O Error: {}", err);
            return Err(Error::new(EIO));
        }
    })
}

pub struct Image {
    file: File
}

impl Image {
    pub fn open(path: &str) -> Result<Image> {
        let file = try_disk!(OpenOptions::new().read(true).write(true).open(path));
        Ok(Image {
            file: file
        })
    }

    pub fn create(path: &str, size: u64) -> Result<Image> {
        let file = try_disk!(OpenOptions::new().read(true).write(true).create(true).open(path));
        try_disk!(file.set_len(size));
        Ok(Image {
            file: file
        })
    }
}

impl Disk for Image {
    fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        try_disk!(self.file.seek(SeekFrom::Start(block * 512)));
        let count = try_disk!(self.file.read(buffer));
        Ok(count)
    }

    fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        try_disk!(self.file.seek(SeekFrom::Start(block * 512)));
        let count = try_disk!(self.file.write(buffer));
        Ok(count)
    }

    fn size(&mut self) -> Result<u64> {
        let size = try_disk!(self.file.seek(SeekFrom::End(0)));
        Ok(size)
    }
}
