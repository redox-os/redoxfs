#![crate_name = "redoxfs"]
#![crate_type = "lib"]

extern crate syscall;
extern crate uuid;

use std::sync::atomic::AtomicUsize;

pub const BLOCK_SIZE: u64 = 4096;
pub const SIGNATURE: &'static [u8; 8] = b"RedoxFS\0";
pub const VERSION: u64 = 4;
pub static IS_UMT: AtomicUsize = AtomicUsize::new(0);

pub use self::archive::{archive, archive_at};
pub use self::disk::{Disk, DiskCache, DiskFile, DiskSparse};
pub use self::extent::Extent;
pub use self::filesystem::FileSystem;
pub use self::header::Header;
pub use self::mount::mount;
pub use self::node::Node;

mod archive;
mod disk;
mod extent;
mod filesystem;
mod header;
mod mount;
mod node;

#[cfg(test)]
mod tests;
