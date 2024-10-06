use syscall::error::Result;

#[cfg(feature = "std")]
pub use self::cache::DiskCache;
#[cfg(feature = "std")]
pub use self::file::DiskFile;
#[cfg(feature = "std")]
pub use self::io::DiskIo;
#[cfg(feature = "std")]
pub use self::sparse::DiskSparse;

#[cfg(feature = "std")]
mod cache;
#[cfg(feature = "std")]
mod file;
#[cfg(feature = "std")]
mod io;
#[cfg(feature = "std")]
mod sparse;

/// A disk
pub trait Disk {
    /// Reads blocks from disk, but use filesystem wrappers instead
    fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize>;

    /// Writes blocks from disk, but use filesystem wrappers instead
    fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize>;

    /// Get size of disk in bytes
    fn size(&mut self) -> Result<u64>;
}
