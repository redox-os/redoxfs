use syscall;
use syscall::{Packet, Scheme};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::Ordering;

use IS_UMT;
use disk::Disk;
use filesystem::FileSystem;

use self::scheme::FileScheme;

pub mod resource;
pub mod scheme;

pub fn mount<D: Disk, P: AsRef<Path>, F: FnMut()>(filesystem: FileSystem<D>, mountpoint: &P, mut callback: F) -> io::Result<()> {
    let mountpoint = mountpoint.as_ref();
    let mut socket = File::create(format!(":{}", mountpoint.display()))?;

    callback();

    syscall::setrens(0, 0).expect("redoxfs: failed to enter null namespace");

    let scheme = FileScheme::new(format!("{}", mountpoint.display()), filesystem);
    loop {
        if IS_UMT.load(Ordering::SeqCst) > 0 {
            break Ok(());
        }

        let mut packet = Packet::default();
        match socket.read(&mut packet) {
            Ok(_ok) => (),
            Err(err) => if err.kind() == io::ErrorKind::Interrupted {
                continue;
            } else {
                break Err(err);
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
