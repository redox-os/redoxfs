use syscall::error::Result;

pub use self::cache::DiskCache;
pub use self::file::DiskFile;
pub use self::sparse::DiskSparse;

mod cache;
mod file;
mod sparse;

/// A disk
pub trait Disk {
    fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize>;
    fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize>;
    fn size(&mut self) -> Result<u64>;
}
