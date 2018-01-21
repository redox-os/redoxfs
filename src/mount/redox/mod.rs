extern crate spin;

use syscall;
use syscall::{Packet, Scheme};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

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
        let mut packet = Packet::default();
        socket.read(&mut packet).unwrap();
        scheme.handle(&mut packet);
        socket.write(&packet).unwrap();
    }
}
