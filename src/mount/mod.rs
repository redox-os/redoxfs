#[cfg(not(target_os = "redox"))]
mod fuse;

#[cfg(not(target_os = "redox"))]
pub use self::fuse::mount;

#[cfg(target_os = "redox")]
mod redox;

#[cfg(target_os = "redox")]
pub use self::redox::mount;
