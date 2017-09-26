use std::io;
use std::fs::File;
use std::path::Path;

use disk::Disk;
use filesystem::FileSystem;

#[cfg(unix)]
mod fuse;

#[cfg(target_os = "redox")]
mod redox;

#[cfg(all(unix, target_os = "macos"))]
pub fn mount<D: Disk, P: AsRef<Path>>(filesystem: FileSystem<D>, mountpoint: &P, mut write: File) -> io::Result<()> {
    use std::ffi::OsStr;
    use std::io::Write;

    let _ = write.write(&[0]);
    drop(write);

    fuse::mount(fuse::Fuse {
        fs: filesystem
    }, mountpoint, &[
        // One of the uses of this redoxfs fuse wrapper is to populate a filesystem
        // while building the Redox OS kernel. This means that we need to write on
        // a filesystem that belongs to `root`, which in turn means that we need to
        // be `root`, thus that we need to allow `root` to have access.
        OsStr::new("-o"),
        OsStr::new("defer_permissions"),
    ])
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn mount<D: Disk, P: AsRef<Path>>(filesystem: FileSystem<D>, mountpoint: &P, mut write: File) -> io::Result<()> {
    use std::io::Write;

    let _ = write.write(&[0]);
    drop(write);

    fuse::mount(fuse::Fuse {
        fs: filesystem
    }, mountpoint, &[])
}

#[cfg(target_os = "redox")]
pub fn mount<D: Disk, P: AsRef<Path>>(filesystem: FileSystem<D>, mountpoint: &P, write: File) -> io::Result<()> {
    redox::mount(filesystem, mountpoint, write)
}
