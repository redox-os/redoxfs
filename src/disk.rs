//use core::result::Result;
use core::fmt::Display;

/// A disk
pub trait Disk<E: Display> {
    fn name(&self) -> &str;
    fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize, E>;
    fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize, E>;
}
