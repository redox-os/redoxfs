use std::io::Result;

/// A disk
pub trait Disk {
    fn name(&self) -> &str;
    fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize>;
    fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize>;
}
