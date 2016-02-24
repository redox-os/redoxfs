extern crate redoxfs;

use std::env;

use redoxfs::{Disk, FileSystem};

use file_disk::FileDisk;

pub mod file_disk;

fn main() {
    let mut args = env::args();
    if let Some(path) = args.nth(1) {
        match FileDisk::new(&path) {
            Ok(disk) => match FileSystem::new(Box::new(disk)) {
                Ok(filesystem) => {
                    let path = args.next().unwrap_or(String::new());
                    for (node_block, node) in filesystem.nodes.iter() {
                        let mut name = "/".to_string();
                        for &b in node.name.iter() {
                            if b == 0 {
                                break;
                            } else {
                                unsafe { name.as_mut_vec().push(b); }
                            }
                        }
                        if name == path {
                            println!("{}: {}", node_block, name);
                            break;
                        } else if name.starts_with(&path) {
                            println!("{}: {}", node_block, name);
                        }
                    }
                },
                Err(err) => {
                    println!("redoxfs: failed to open filesystem: {}", err);
                }
            },
            Err(err) => {
                println!("redoxfs: failed to open disk: {}", err);
            }
        }
    } else {
        println!("redoxfs: no disk image provided");
    }
}
