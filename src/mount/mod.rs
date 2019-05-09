use std::io;
use std::path::Path;

use disk::Disk;
use filesystem::FileSystem;

#[cfg(not(target_os = "redox"))]
mod fuse;

#[cfg(target_os = "redox")]
mod redox;

#[cfg(target_os = "macos")]
pub fn mount<D: Disk, P: AsRef<Path>, F: FnMut()>(filesystem: FileSystem<D>, mountpoint: &P, callback: F) -> io::Result<()> {
    use std::ffi::OsStr;

    fuse::mount(filesystem, mountpoint, callback, &[
        // One of the uses of this redoxfs fuse wrapper is to populate a filesystem
        // while building the Redox OS kernel. This means that we need to write on
        // a filesystem that belongs to `root`, which in turn means that we need to
        // be `root`, thus that we need to allow `root` to have access.
        OsStr::new("-o"),
        OsStr::new("defer_permissions"),
    ])
}

#[cfg(all(not(target_os = "macos"), not(target_os = "redox")))]
pub fn mount<D: Disk, P: AsRef<Path>, F: FnMut()>(filesystem: FileSystem<D>, mountpoint: &P, callback: F) -> io::Result<()> {
    fuse::mount(filesystem, mountpoint, callback, &[])
}

#[cfg(target_os = "redox")]
pub fn mount<D: Disk, P: AsRef<Path>, F: FnMut()>(filesystem: FileSystem<D>, mountpoint: &P, callback: F) -> io::Result<()> {
    redox::mount(filesystem, mountpoint, callback)
}
