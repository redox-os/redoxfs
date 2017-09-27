extern crate spin;

use syscall::{Packet, Scheme};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use disk::Disk;

use self::scheme::FileScheme;

pub mod resource;
pub mod scheme;

pub fn mount<D: Disk, P: AsRef<Path>>(filesystem: filesystem::FileSystem<D>, mountpoint: &P, mut write: File) -> io::Result<()> {
    let mountpoint = mountpoint.as_ref();
    let mut socket = File::create(format!(":{}", mountpoint.display()))?;

    println!("redoxfs: mounted filesystem on {}:", mountpoint.display());

    let _ = write.write(&[0]);
    drop(write);

    let scheme = FileScheme::new(format!("{}", mountpoint.display()), filesystem);
    loop {
        let mut packet = Packet::default();
        socket.read(&mut packet).unwrap();
        scheme.handle(&mut packet);
        socket.write(&packet).unwrap();
    }

    Ok(())
}
