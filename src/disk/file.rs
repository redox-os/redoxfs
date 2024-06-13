use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use syscall::error::{Result, Error, EIO};

#[cfg(target_os = "redox")]
use std::os::fd::AsRawFd;

use crate::disk::Disk;
use crate::BLOCK_SIZE;

pub struct DiskFile {
    pub file: File,
}

trait ResultExt {
    type T;
    fn or_eio(self) -> Result<Self::T>;
}
impl<T> ResultExt for Result<T> {
    type T = T;
    fn or_eio(self) -> Result<Self::T> {
        match self {
            Ok(t) => Ok(t),
            Err(err) => {
                eprintln!("RedoxFS: IO ERROR: {err}");
                Err(Error::new(EIO))
            }
        }
    }
}
impl<T> ResultExt for std::io::Result<T> {
    type T = T;
    fn or_eio(self) -> Result<Self::T> {
        match self {
            Ok(t) => Ok(t),
            Err(err) => {
                eprintln!("RedoxFS: IO ERROR: {err}");
                Err(Error::new(EIO))
            }
        }
    }
}

impl DiskFile {
    pub fn open(path: impl AsRef<Path>) -> Result<DiskFile> {
        let file = OpenOptions::new().read(true).write(true).open(path).or_eio()?;
        Ok(DiskFile { file })
    }

    pub fn create(path: impl AsRef<Path>, size: u64) -> Result<DiskFile> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .or_eio()?;
        file.set_len(size).or_eio()?;
        Ok(DiskFile { file })
    }
}

impl Disk for DiskFile {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        #[cfg(target_os = "redox")]
        unsafe {
            syscall::syscall5(syscall::SYS_READ2, self.file.as_raw_fd() as usize, buffer.as_mut_ptr() as usize, buffer.len(), (block * BLOCK_SIZE) as usize, 0)
                .or_eio()
        }
        #[cfg(not(target_os = "redox"))]
        {
            self.file.seek(SeekFrom::Start(block * BLOCK_SIZE)).or_eio()?;
            self.file.read(buffer).or_eio()
        }
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        #[cfg(target_os = "redox")]
        unsafe {
            syscall::syscall5(syscall::SYS_WRITE2, self.file.as_raw_fd() as usize, buffer.as_ptr() as usize, buffer.len(), (block * BLOCK_SIZE) as usize, 0)
                .or_eio()
        }
        #[cfg(not(target_os = "redox"))]
        {
            self.file.seek(SeekFrom::Start(block * BLOCK_SIZE)).or_eio()?;
            self.file.write(buffer).or_eio()
        }
    }

    fn size(&mut self) -> Result<u64> {
        self.file.seek(SeekFrom::End(0)).or_eio()
    }
}
