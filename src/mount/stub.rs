use std::{io, path::Path};

use crate::{filesystem, Disk};

pub fn mount<D, P, T, F>(
    mut _filesystem: filesystem::FileSystem<D>,
    _mountpoint: P,
    _callback: F,
) -> io::Result<T>
where
    D: Disk,
    P: AsRef<Path>,
    F: FnOnce(&Path) -> T,
{
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "FUSE mount feature is disabled",
    ))
}
