#![deny(warnings)]

extern crate redoxfs;
extern crate spin;
extern crate syscall;

use std::{env, process};
use std::fs::File;
use std::io::{Read, Write};

use cache::Cache;
use image::Image;
use scheme::FileScheme;

use redoxfs::FileSystem;

use syscall::{Packet, Scheme};

pub mod cache;
pub mod image;
pub mod resource;
pub mod scheme;

fn main() {
    if let Some(path) = env::args().nth(1) {
        let mut pipes = [0; 2];
        syscall::pipe2(&mut pipes, 0).unwrap();

        // Daemonize
        if unsafe { syscall::clone(0).unwrap() } == 0 {
            let _ = syscall::close(pipes[0]);

            match Image::open(&path).map(|image| Cache::new(image)) {
                Ok(disk) => match FileSystem::open(Box::new(disk)) {
                    Ok(fs) => match File::create(":file") {
                        Ok(mut socket) => {
                            println!("redoxfs: mounted filesystem {} on file:", path);

                            let _ = syscall::write(pipes[1], &[1]);

                            let scheme = FileScheme::new("file", fs);
                            loop {
                                let mut packet = Packet::default();
                                socket.read(&mut packet).unwrap();
                                scheme.handle(&mut packet);
                                socket.write(&packet).unwrap();
                            }
                        },
                        Err(err) => println!("redoxfs: failed to create file scheme: {}", err)
                    },
                    Err(err) => println!("redoxfs: failed to open filesystem {}: {}", path, err)
                },
                Err(err) => println!("redoxfs: failed to open image {}: {}", path, err)
            }

            let _ = syscall::write(pipes[1], &[0]);

            let _ = syscall::close(pipes[1]);
        } else {
            let _ = syscall::close(pipes[1]);

            let mut res = [0];
            syscall::read(pipes[0], &mut res).unwrap();

            let _ = syscall::close(pipes[0]);

            process::exit(res[0] as i32);
        }
    } else {
        println!("redoxfs: no disk image provided");
    }
}
