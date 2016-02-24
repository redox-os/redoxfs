extern crate redoxfs;

use std::env;
use std::io::{self, Write};

use redoxfs::{Disk, FileSystem};

use file_disk::FileDisk;

pub mod file_disk;

fn shell<E>(filesystem: FileSystem<E>){
    let mut stdout = io::stdout();
    let stdin = io::stdin();

    loop {
        stdout.write(b"redoxfs# ").unwrap();
        stdout.flush().unwrap();

        let mut line = String::new();
        stdin.read_line(&mut line).unwrap();

        let mut args = line.trim().split(' ');
        if let Some(command) = args.next() {
            match command {
                "" => (),
                "ls" => {
                    let path = args.next().unwrap_or("/");
                    for (node_block, node) in filesystem.nodes.iter() {
                        let mut name = "/".to_string();
                        for &b in node.name.iter() {
                            if b == 0 {
                                break;
                            } else {
                                unsafe { name.as_mut_vec().push(b); }
                            }
                        }
                        if name.starts_with(&path) {
                            println!("{}: {}", node_block, name);
                        }
                    }
                },
                _ => println!("unknown command: {}", command)
            }
        }
    }
}

fn main() {
    let mut args = env::args();
    if let Some(path) = args.nth(1) {
        match FileDisk::new(&path) {
            Ok(disk) => match FileSystem::new(Box::new(disk)) {
                Ok(filesystem) => shell(filesystem),
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
