#![deny(warnings)]

extern crate redoxfs;
extern crate syscall;

use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::str;

use redoxfs::{FileSystem, Node};

use image::Image;

pub mod image;

fn shell(mut fs: FileSystem){
    let mut block = fs.header.1.root;

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
                            Ok(block) => match fs.node(block) {
                                Ok(node) => println!("{}: {:#?}", node.0, node.1),
                                Err(err) => println!("node: failed to read {}: {}", block, err)
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
                "cat" => {
                    if let Some(arg) = args.next() {
                        match fs.find_node(arg, block) {
                            Ok(node) => {
                                println!("{}: {:#?}", node.0, node.1);

                                let mut data = [0; 512];
                                match fs.read_node(node.0, 0, &mut data) {
                                    Ok(count) => println!("cat: read {} bytes\n{}", count, unsafe { str::from_utf8_unchecked(&data) }),
                                    Err(err) => println!("cat: failed to read {}: {}", node.0, err)
                                }
                            }
                            Err(err) => println!("cat: failed to create {}: {}", arg, err)
                        }
                    } else {
                        println!("cat <path>");
                    }
                },
                "cd" => {
                    if let Some(arg) = args.next() {
                        if arg == "." {

                        } else if arg == ".." {
                            match fs.node(block) {
                                Ok(node) => if node.1.parent > 0 {
                                    block = node.1.parent;
                                    println!("cd: {}", block);
                                } else {
                                    println!("cd: no parent directory {}", block);
                                },
                                Err(err) => println!("cd: failed to read {}: {}", block, err)
                            }
                        } else {
                            match fs.find_node(arg, block) {
                                Ok(node) => if node.1.is_dir() {
                                    block = node.0;
                                    println!("cd: {}", block);
                                } else {
                                    println!("cd: not a dir {}", arg);
                                },
                                Err(err) => println!("cd: failed to read {}: {}", arg, err)
                            }
                        }
                    } else {
                        println!("cd <path>");
                    }
                },
                "ed" => {
                    if let Some(arg) = args.next() {
                        match fs.create_node(Node::MODE_FILE, arg, block) {
                            Ok(node) => {
                                println!("{}: {:#?}", node.0, node.1);

                                let mut data = String::new();
                                loop {
                                    let mut line = String::new();
                                    stdin.read_line(&mut line).unwrap();

                                    if line.is_empty() || line == ".\n" {
                                        break;
                                    } else {
                                        data.push_str(&line);
                                    }
                                }
                                println!("{}:\n{}", arg, data);

                                match fs.write_node(node.0, 0, &data.as_bytes()) {
                                    Ok(count) => println!("ed: wrote {} bytes", count),
                                    Err(err) => println!("ed: failed to write {}: {}", node.0, err)
                                }
                            }
                            Err(err) => println!("ed: failed to create {}: {}", arg, err)
                        }
                    } else {
                        println!("ed <path>");
                    }
                },
                "find" => {
                    if let Some(arg) = args.next() {
                        match fs.find_node(arg, block) {
                            Ok(node) => println!("{}: {:#?}", node.0, node.1),
                            Err(err) => println!("find: failed to read {}: {}", arg, err)
                        }
                    } else {
                        println!("find <path>");
                    }
                },
                "ls" => {
                    let mut children = Vec::new();
                    match fs.child_nodes(&mut children, block) {
                        Ok(()) => for node in children.iter() {
                            println!("{}: {:#?}", node.0, node.1);
                        },
                        Err(err) => println!("ls: failed to read {}: {}", block, err)
                    }
                },
                "mk" => {
                    if let Some(arg) = args.next() {
                        match fs.create_node(Node::MODE_FILE, arg, block) {
                            Ok(node) => println!("{}: {:#?}", node.0, node.1),
                            Err(err) => println!("mk: failed to create {}: {}", arg, err)
                        }
                    } else {
                        println!("mk <file>");
                    }
                },
                "mkdir" => {
                    if let Some(arg) = args.next() {
                        match fs.create_node(Node::MODE_DIR, arg, block) {
                            Ok(node) => println!("{}: {:#?}", node.0, node.1),
                            Err(err) => println!("mkdir: failed to create {}: {}", arg, err)
                        }
                    } else {
                        println!("mkdir <dir>");
                    }
                },
                "rm" => {
                    if let Some(arg) = args.next() {
                        match fs.remove_node(Node::MODE_FILE, arg, block) {
                            Ok(()) => println!("rm {}", arg),
                            Err(err) => println!("rm: failed to remove {}: {}", arg, err)
                        }
                    } else {
                        println!("rm <file>");
                    }
                },
                "rmdir" => {
                    if let Some(arg) = args.next() {
                        match fs.remove_node(Node::MODE_DIR, arg, block) {
                            Ok(()) => println!("rmdir {}", arg),
                            Err(err) => println!("rmdir: failed to remove {}: {}", arg, err)
                        }
                    } else {
                        println!("rmdir <dir>");
                    }
                },
                _ => println!("commands: exit header node root free cat ed find ls mk mkdir rm rmdir")
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
                    Ok(filesystem) => {
                        println!("redoxfs: opened filesystem {}", path);
                        shell(filesystem);
                    },
                    Err(err) => println!("redoxfs: failed to open filesystem {}: {}", path, err)
                },
                Err(err) => println!("redoxfs: failed to open image {}: {}", path, err)
            }
        }else if let Some(size_str) = args.next() {
            let size = size_str.parse::<u64>().expect("redoxfs: size is not a valid number") * 1024 * 1024;
            match Image::create(&path, size) {
                Ok(disk) => match FileSystem::create(Box::new(disk)) {
                    Ok(filesystem) => {
                        println!("redoxfs: created filesystem {}", path);
                        shell(filesystem);
                    },
                    Err(err) => println!("redoxfs: failed to create filesystem {}: {}", path, err)
                },
                Err(err) => println!("redoxfs: failed to create image {}: {}", path, err)
            }
        } else {
            println!("redoxfs: no size provided");
        }
    } else {
        println!("redoxfs: no disk image provided");
    }
}
