extern crate redoxfs;

extern crate system;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;

use image::Image;
use scheme::FileScheme;

use redoxfs::FileSystem;

use system::scheme::{Packet, Scheme};

pub mod image;
pub mod resource;
pub mod scheme;

fn scheme(fs: FileSystem) {
   //In order to handle example:, we create :example
   let mut scheme = FileScheme::new(fs);
   let mut socket = File::create(":redoxfs").unwrap();
   loop {
       let mut packet = Packet::default();
       while socket.read(&mut packet).unwrap() == size_of::<Packet>() {
           scheme.handle(&mut packet);
           socket.write(&packet).unwrap();
       }
   }
}

fn main() {
    let mut args = env::args();
    if let Some(path) = args.nth(1) {
        //Open an existing image
        match Image::open(&path) {
            Ok(disk) => match FileSystem::open(Box::new(disk)) {
                Ok(filesystem) => {
                    println!("redoxfs: opened filesystem {}", path);
                    scheme(filesystem);
                },
                Err(err) => println!("redoxfs: failed to open filesystem {}: {}", path, err)
            },
            Err(err) => println!("redoxfs: failed to open image {}: {}", path, err)
        }
    } else {
        println!("redoxfs: no disk image provided");
    }
}
