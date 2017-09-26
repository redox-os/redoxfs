extern crate spin;

use syscall::{Packet, Scheme};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use self::scheme::FileScheme;

pub mod resource;
pub mod scheme;

pub fn mount<P: AsRef<Path>>(filesystem: filesystem::FileSystem, mountpoint: &P, mut write: File) {
    let mountpoint = mountpoint.as_ref();
    match File::create(format!(":{}", mountpoint.display())) {
        Ok(mut socket) => {
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
        },
        Err(err) => println!("redoxfs: failed to create {} scheme: {}", mountpoint.display(), err)
    }
}
