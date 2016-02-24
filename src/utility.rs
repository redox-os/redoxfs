extern crate redoxfs;

use std::fs::File;
use std::io::{Result, Read, Write, Seek, SeekFrom};
use std::str;

use redoxfs::{Disk, FileSystem};

pub struct FileDisk {
    path: String,
    file: File
}

impl FileDisk {
    pub fn new(path: &str) -> Result<FileDisk> {
        let file = try!(File::open(path));
        Ok(FileDisk {
            path: path.to_string(),
            file: file
        })
    }
}

impl Disk for FileDisk {
    fn name(&self) -> &str {
        &self.path
    }

    fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        try!(self.file.seek(SeekFrom::Start(block * 512)));
        self.file.read(buffer)
    }

    fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        try!(self.file.seek(SeekFrom::Start(block * 512)));
        self.file.write(buffer)
    }
}

fn main() {
    let disk = FileDisk::new("../../build/i386-unknown-redox/debug/harddrive.bin").unwrap();
    let filesystem = FileSystem::new(Box::new(disk)).unwrap();
    for (node_block, node) in filesystem.nodes.iter() {
        let name = unsafe { str::from_utf8_unchecked(&node.name) };
        println!("{}: {}", node_block, name);
    }
}
