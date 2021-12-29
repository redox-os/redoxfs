#![crate_name = "redoxfs"]
#![crate_type = "lib"]
#![cfg_attr(not(feature = "std"), no_std)]
// Used often in generating redox_syscall errors
#![allow(clippy::or_fun_call)]

extern crate alloc;

use core::sync::atomic::AtomicUsize;

pub const BLOCK_SIZE: u64 = 4096;
pub const SIGNATURE: &[u8; 8] = b"RedoxFS\0";
pub const VERSION: u64 = 5;
pub static IS_UMT: AtomicUsize = AtomicUsize::new(0);

pub use self::allocator::{AllocEntry, AllocList, Allocator, ALLOC_LIST_ENTRIES};
#[cfg(feature = "std")]
pub use self::archive::{archive, archive_at};
pub use self::block::{BlockData, BlockList, BlockPtr, BlockRaw};
pub use self::dir::{DirEntry, DirList};
pub use self::disk::*;
pub use self::filesystem::FileSystem;
pub use self::header::{Header, HEADER_RING};
pub use self::key::{Key, KeySlot, Salt};
#[cfg(feature = "std")]
pub use self::mount::mount;
pub use self::node::{Node, NodeLevel};
pub use self::transaction::Transaction;
pub use self::tree::{Tree, TreeData, TreeList, TreePtr};

mod allocator;
#[cfg(feature = "std")]
mod archive;
mod block;
mod dir;
mod disk;
mod filesystem;
mod header;
mod key;
#[cfg(feature = "std")]
mod mount;
mod node;
mod transaction;
mod tree;

#[cfg(all(feature = "std", test))]
mod tests;
