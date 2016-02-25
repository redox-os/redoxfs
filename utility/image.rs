use std::fs::{File, OpenOptions};
use std::io::{Error, Read, Write, Seek, SeekFrom};

use redoxfs::Disk;

pub struct Image {
    file: File
}

impl Image {
    pub fn open(path: &str) -> Result<Image, Error> {
        let file = try!(OpenOptions::new().read(true).write(true).open(path));
        Ok(Image {
            file: file
        })
    }

    pub fn create(path: &str, size: u64) -> Result<Image, Error> {
        let file = try!(OpenOptions::new().read(true).write(true).create(true).open(path));
        try!(file.set_len(size));
        Ok(Image {
            file: file
        })
    }
}

impl Disk<Error> for Image {
    fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize, Error> {
        try!(self.file.seek(SeekFrom::Start(block * 512)));
        self.file.read(buffer)
    }

    fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize, Error> {
        try!(self.file.seek(SeekFrom::Start(block * 512)));
        self.file.write(buffer)
    }

    fn size(&mut self) -> Result<u64, Error> {
        self.file.seek(SeekFrom::End(0))
    }
}
