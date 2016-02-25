/// A disk
pub trait Disk<E> {
    fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize, E>;
    fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize, E>;
}
