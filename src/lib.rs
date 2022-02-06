#![crate_name = "redoxfs"]
#![crate_type = "lib"]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate core;

extern crate syscall;
extern crate uuid;

use core::sync::atomic::AtomicUsize;

pub const BLOCK_SIZE: u64 = 4096;
pub const SIGNATURE: &'static [u8; 8] = b"RedoxFS\0";
pub const VERSION: u64 = 4;
pub static IS_UMT: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "std")]
pub use self::archive::{archive, archive_at};
pub use self::disk::Disk;
#[cfg(feature = "std")]
pub use self::disk::{DiskCache, DiskFile, DiskSparse};
pub use self::extent::Extent;
pub use self::filesystem::FileSystem;
pub use self::header::Header;
#[cfg(feature = "std")]
pub use self::mount::mount;
pub use self::node::Node;

#[cfg(feature = "std")]
mod archive;
mod disk;
mod extent;
mod filesystem;
mod header;
#[cfg(feature = "std")]
mod mount;
mod node;

#[cfg(all(feature = "std", test))]
mod tests;
