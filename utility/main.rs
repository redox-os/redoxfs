#![deny(warnings)]

extern crate redoxfs;

use std::env;
use std::fmt::Display;
use std::io::{self, Write};
use std::path::Path;

use redoxfs::{FileSystem, Node};

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
                "header" => println!("{:#?}", fs.header),
                "node" => {
                    if let Some(arg) = args.next() {
                        match arg.parse::<u64>() {
                            Ok(block) => {
                                match fs.node(block) {
                                    Ok(node) => println!("{}: {:#?}", node.0, node.1),
                                    Err(err) => println!("node: failed to read {}: {}", block, err)
                                }
                            },
                            Err(err) => println!("node: invalid block {}: {}", arg, err)
                        }
                    } else {
                        println!("node <block>");
                    }
                },
                "root" => {
                    let block = fs.header.1.root;
                    match fs.node(block) {
                        Ok(node) => println!("{}: {:#?}", node.0, node.1),
                        Err(err) => println!("node: failed to read {}: {}", block, err)
                    }
                },
                "free" => {
                    let block = fs.header.1.free;
                    match fs.node(block) {
                        Ok(node) => println!("{}: {:#?}", node.0, node.1),
                        Err(err) => println!("node: failed to read {}: {}", block, err)
                    }
                },
                "find" => {
                    if let Some(arg) = args.next() {
                        let root_block = fs.header.1.root;
                        match fs.find_node(arg, root_block) {
                            Ok(node_option) => match node_option {
                                Some(node) => println!("{}: {:#?}", node.0, node.1),
                                None => println!("find: did not find {}", arg)
                            },
                            Err(err) => println!("find: failed to read {}: {}", arg, err)
                        }
                    } else {
                        println!("find <path>");
                    }
                },
                "ls" => {
                    let root_block = fs.header.1.root;
                    let mut children = Vec::new();
                    match fs.child_nodes(&mut children, root_block) {
                        Ok(()) => for node in children.iter() {
                            println!("{}: {:#?}", node.0, node.1);
                        },
                        Err(err) => println!("ls: failed to read {}: {}", root_block, err)
                    }
                },
                "mkdir" => {
                    if let Some(arg) = args.next() {
                        let root_block = fs.header.1.root;
                        match fs.create_node(arg, Node::MODE_DIR, root_block) {
                            Ok(node_option) => match node_option {
                                Some(node) => println!("{}: {:#?}", node.0, node.1),
                                None => println!("mkdir: not enough space for {}", arg)
                            },
                            Err(err) => println!("mkdir: failed to create {}: {}", arg, err)
                        }
                    } else {
                        println!("mkdir <file>");
                    }
                },
                "touch" => {
                    if let Some(arg) = args.next() {
                        let root_block = fs.header.1.root;
                        match fs.create_node(arg, Node::MODE_FILE, root_block) {
                            Ok(node_option) => match node_option {
                                Some(node) => println!("{}: {:#?}", node.0, node.1),
                                None => println!("touch: not enough space for {}", arg)
                            },
                            Err(err) => println!("touch: failed to create {}: {}", arg, err)
                        }
                    } else {
                        println!("touch <file>");
                    }
                },
                _ => println!("commands: exit header node root free find ls mkdir touch")
            }
        }
    }
}

fn main() {
    let mut args = env::args();
    if let Some(path) = args.nth(1) {
        if Path::new(&path).exists() {
            //Open an existing image
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
            //Create a 1 GB disk image
            let size = 1024 * 1024 * 1024;
            match Image::create(&path, size) {
                Ok(disk) => match FileSystem::create(Box::new(disk)) {
                    Ok(filesystem_option) => match filesystem_option {
                        Some(filesystem) => {
                            println!("redoxfs: created filesystem {}", path);
                            shell(filesystem);
                        },
                        None => println!("redoxfs: not enough space for filesystem on {}", path)
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
