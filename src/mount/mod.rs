#[cfg(all(not(target_os = "redox"), not(fuzzing)))]
mod fuse;
#[cfg(all(not(target_os = "redox"), fuzzing))]
pub mod fuse;

#[cfg(not(target_os = "redox"))]
pub use self::fuse::mount;

#[cfg(target_os = "redox")]
mod redox;

#[cfg(target_os = "redox")]
pub use self::redox::mount;
