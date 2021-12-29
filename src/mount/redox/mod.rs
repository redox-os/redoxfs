use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::Ordering;
use syscall::{Packet, SchemeMut};

use crate::{Disk, FileSystem, IS_UMT};

use self::scheme::FileScheme;

pub mod resource;
pub mod scheme;

pub fn mount<D, P, T, F>(filesystem: FileSystem<D>, mountpoint: P, mut callback: F) -> io::Result<T>
where
    D: Disk,
    P: AsRef<Path>,
    F: FnMut(&Path) -> T,
{
    let mountpoint = mountpoint.as_ref();
    let socket_path = format!(":{}", mountpoint.display());
    let mut socket = File::create(&socket_path)?;

    let mounted_path = format!("{}:", mountpoint.display());
    let res = callback(Path::new(&mounted_path));

    let mut scheme = FileScheme::new(format!("{}", mountpoint.display()), filesystem);
    loop {
        if IS_UMT.load(Ordering::SeqCst) > 0 {
            break Ok(res);
        }

        let mut packet = Packet::default();
        match socket.read(&mut packet) {
            Ok(0) => break Ok(res),
            Ok(_ok) => (),
            Err(err) => {
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                } else {
                    break Err(err);
                }
            }
        }

        scheme.handle(&mut packet);

        match socket.write(&packet) {
            Ok(_ok) => (),
            Err(err) => {
                break Err(err);
            }
        }
    }
}
