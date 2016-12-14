#![deny(warnings)]

extern crate redoxfs;
extern crate syscall;

use std::env;
use std::str;

use redoxfs::FileSystem;

use image::Image;

pub mod image;

fn main() {
    let mut args = env::args();
    if let Some(path) = args.nth(1) {
        //Open an existing image
        match Image::open(&path) {
            Ok(disk) => match FileSystem::create(Box::new(disk)) {
                Ok(filesystem) => {
                    println!("redoxfs: created filesystem on {}, size {} MB", path, filesystem.header.1.size/1024/1024);
                },
                Err(err) => println!("redoxfs: failed to create filesystem on {}: {}", path, err)
            },
            Err(err) => println!("redoxfs: failed to open image {}: {}", path, err)
        }
    } else {
        println!("redoxfs: no disk image provided");
    }
}
