#![deny(warnings)]

extern crate redoxfs;
extern crate syscall;

use std::{env, process, str, time};

use redoxfs::FileSystem;

use image::Image;

pub mod image;

fn main() {
    let mut args = env::args();
    if let Some(path) = args.nth(1) {
        let ctime = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();

        //Open an existing image
        match Image::open(&path) {
            Ok(disk) => match FileSystem::create(Box::new(disk), ctime.as_secs(), ctime.subsec_nanos()) {
                Ok(filesystem) => {
                    println!("redoxfs-mkfs: created filesystem on {}, size {} MB", path, filesystem.header.1.size/1024/1024);
                },
                Err(err) => {
                    println!("redoxfs-mkfs: failed to create filesystem on {}: {}", path, err);
                    process::exit(1);
                }
            },
            Err(err) => {
                println!("redoxfs-mkfs: failed to open image {}: {}", path, err);
                process::exit(1);
            }
        }
    } else {
        println!("redoxfs-mkfs: no disk image provided");
        println!("redoxfs-mkfs [disk]");
        process::exit(1);
    }
}
