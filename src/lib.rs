#![crate_name="redoxfs"]
#![crate_type="lib"]
#![feature(inclusive_range_syntax)]

#![deny(warnings)]

extern crate syscall;

pub use self::disk::Disk;
pub use self::ex_node::ExNode;
pub use self::extent::Extent;
pub use self::filesystem::FileSystem;
pub use self::header::Header;
pub use self::node::Node;
pub use self::filename::FileNameBuf;
pub use self::filename::FileName;
pub use self::filename::FileNameError;

pub mod disk;
pub mod ex_node;
pub mod extent;
pub mod filesystem;
pub mod header;
pub mod node;
pub mod filename;