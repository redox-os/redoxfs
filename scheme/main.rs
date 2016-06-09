#![deny(warnings)]

extern crate redoxfs;

extern crate system;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use std::thread;

use cache::Cache;
use image::Image;
use scheme::FileScheme;

use redoxfs::FileSystem;

use system::scheme::{Packet, Scheme};

pub mod cache;
pub mod image;
pub mod resource;
pub mod scheme;

enum Status {
    Starting,
    Running,
    Stopping
}

fn main() {
    if let Some(path) = env::args().nth(1) {
        let status_mutex = Arc::new(Mutex::new(Status::Starting));

        let status_daemon = status_mutex.clone();
        thread::spawn(move || {
            match Image::open(&path).map(|image| Cache::new(image)) {
                Ok(disk) => match FileSystem::open(Box::new(disk)) {
                    Ok(fs) => match File::create(":file") {
                        Ok(mut socket) => {
                            println!("redoxfs: mounted filesystem {} on file:", path);

                            *status_daemon.lock().unwrap() = Status::Running;

                            let mut scheme = FileScheme::new(fs);
                            loop {
                                let mut packet = Packet::default();
                                while socket.read(&mut packet).unwrap() == size_of::<Packet>() {
                                    scheme.handle(&mut packet);
                                    socket.write(&packet).unwrap();
                                }
                            }
                        },
                        Err(err) => println!("redoxfs: failed to create file scheme: {}", err)
                    },
                    Err(err) => println!("redoxfs: failed to open filesystem {}: {}", path, err)
                },
                Err(err) => println!("redoxfs: failed to open image {}: {}", path, err)
            }

            *status_daemon.lock().unwrap() = Status::Stopping;
        });

        'waiting: loop {
            match *status_mutex.lock().unwrap() {
                Status::Starting => (),
                Status::Running => break 'waiting,
                Status::Stopping => break 'waiting,
            }

            thread::sleep_ms(30);
        }
    } else {
        println!("redoxfs: no disk image provided");
    }
}
