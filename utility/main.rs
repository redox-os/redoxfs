#![deny(warnings)]

extern crate redoxfs;

use std::env;
use std::fmt::Display;
use std::io::{self, Write};
use std::path::Path;

use redoxfs::FileSystem;

use image::Image;

pub mod image;

fn shell<E: Display>(mut fs: FileSystem<E>){
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
                "exit" => break,
                "header" => {
                    println!("{:#?}", fs.header);
                },
                "node" => {
                    if let Some(arg) = args.next() {
                        match arg.parse::<u64>() {
                            Ok(block) => {
                                match fs.node(block) {
                                    Ok(node) => println!("{:#?}", node),
                                    Err(err) => println!("node: failed to read {}: {}", block, err)
                                }
                            },
                            Err(err) => println!("node: invalid block {}: {}", arg, err)
                        }
                    } else {
                        println!("node <block>")
                    }
                },
                "ls" => {
                    /*
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
                    */
                    println!("TODO: ls");
                },
                _ => println!("unknown command: {}", command)
            }
        }
    }
}

fn main() {
    let mut args = env::args();
    if let Some(path) = args.nth(1) {
        if Path::new(&path).exists() {
            match Image::open(&path) {
                Ok(disk) => match FileSystem::open(Box::new(disk)) {
                    Ok(filesystem_option) => match filesystem_option {
                        Some(filesystem) => {
                            println!("redoxfs: opened filesystem {}", path);
                            shell(filesystem);
                        },
                        None => println!("redoxfs: no filesystem found in {}", path)
                    },
                    Err(err) => println!("redoxfs: failed to open filesystem {}: {}", path, err)
                },
                Err(err) => println!("redoxfs: failed to open image {}: {}", path, err)
            }
        }else{
            match Image::create(&path) {
                Ok(disk) => match FileSystem::create(Box::new(disk)) {
                    Ok(filesystem) => {
                        println!("redoxfs: created filesystem {}", path);
                        shell(filesystem);
                    },
                    Err(err) => println!("redoxfs: failed to create filesystem {}: {}", path, err)
                },
                Err(err) => println!("redoxfs: failed to create image {}: {}", path, err)
            }
        }
    } else {
        println!("redoxfs: no disk image provided");
    }
}
