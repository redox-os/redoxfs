#![crate_name = "redoxfs"]
#![crate_type = "lib"]
#![cfg_attr(not(feature = "std"), no_std)]
// Used often in generating redox_syscall errors
#![allow(clippy::or_fun_call)]
#![allow(unexpected_cfgs)]

extern crate alloc;

use core::sync::atomic::AtomicUsize;

pub const BLOCK_SIZE: u64 = 4096;
// A record is 4KiB << 5 = 128KiB
pub const RECORD_LEVEL: usize = 5;
pub const RECORD_SIZE: u64 = BLOCK_SIZE << RECORD_LEVEL;
pub const SIGNATURE: &[u8; 8] = b"RedoxFS\0";
pub const VERSION: u64 = 6;
pub const DIR_ENTRY_MAX_LENGTH: usize = 252;

pub static IS_UMT: AtomicUsize = AtomicUsize::new(0);

pub use self::allocator::{AllocEntry, AllocList, Allocator, ALLOC_LIST_ENTRIES};
#[cfg(feature = "std")]
pub use self::archive::{archive, archive_at};
pub use self::block::{
    BlockAddr, BlockData, BlockLevel, BlockList, BlockPtr, BlockRaw, BlockTrait,
};
pub use self::dir::{DirEntry, DirList};
pub use self::disk::*;
pub use self::filesystem::FileSystem;
pub use self::header::{Header, HEADER_RING};
pub use self::key::{Key, KeySlot, Salt};
#[cfg(feature = "std")]
pub use self::mount::mount;
pub use self::node::{Node, NodeLevel};
pub use self::record::RecordRaw;
pub use self::transaction::Transaction;
pub use self::tree::{Tree, TreeData, TreeList, TreePtr};
#[cfg(feature = "std")]
pub use self::unmount::unmount_path;

mod allocator;
#[cfg(feature = "std")]
mod archive;
mod block;
mod dir;
mod disk;
mod filesystem;
mod header;
mod key;
#[cfg(all(feature = "std", not(fuzzing)))]
mod mount;
#[cfg(all(feature = "std", fuzzing))]
pub mod mount;
mod node;
mod record;
mod transaction;
mod tree;
#[cfg(feature = "std")]
mod unmount;

#[cfg(all(feature = "std", test))]
mod tests;
