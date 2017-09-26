#![deny(warnings)]
#![cfg_attr(unix, feature(libc))]

#[cfg(unix)]
extern crate libc;

extern crate redoxfs;

use std::env;
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::process;

use redoxfs::{DiskCache, DiskFile, mount};

#[cfg(unix)]
fn fork() -> isize {
    unsafe { libc::fork() as isize }
}

#[cfg(unix)]
fn pipe(pipes: &mut [i32; 2]) -> isize {
    unsafe { libc::pipe(pipes.as_mut_ptr()) as isize }
}

#[cfg(target_os = "redox")]
fn fork() -> isize {
    unsafe { syscall::Error::mux(syscall::clone(0)) as isize }
}

#[cfg(target_os = "redox")]
fn pipe(pipes: &mut [usize; 2]) -> isize {
    syscall::Error::mux(syscall::pipe2(pipes, 0)) as isize
}

#[cfg(target_os = "redox")]
fn mount<P: AsRef<Path>>(filesystem: redoxfs::FileSystem, mountpoint: &P, write: File) {
    redox::mount(filesystem, mountpoint, write);
}

fn usage() {
    println!("redoxfs [disk] [mountpoint]");
}

fn main() {
    use std::io::{Read, Write};

    let mut pipes = [0; 2];
    if pipe(&mut pipes) == 0 {
        let mut read = unsafe { File::from_raw_fd(pipes[0]) };
        let mut write = unsafe { File::from_raw_fd(pipes[1]) };

        let pid = fork();
        if pid == 0 {
            drop(read);

            if let Some(path) = env::args().nth(1) {
                //Open an existing image
                match DiskFile::open(&path).map(|image| DiskCache::new(image)) {
                    Ok(disk) => match redoxfs::FileSystem::open(disk) {
                        Ok(filesystem) => {
                            println!("redoxfs: opened filesystem {}", path);

                            if let Some(mountpoint) = env::args().nth(2) {
                                match mount(filesystem, &mountpoint, write) {
                                    Ok(()) => {
                                        process::exit(0);
                                    },
                                    Err(err) => {
                                        println!("redoxfs: failed to mount {} to {}: {}", path, mountpoint, err);
                                        process::exit(1);
                                    }
                                }
                            } else {
                                println!("redoxfs: no mount point provided");
                                usage();
                            }
                        },
                        Err(err) => println!("redoxfs: failed to open filesystem {}: {}", path, err)
                    },
                    Err(err) => println!("redoxfs: failed to open image {}: {}", path, err)
                }

                let _ = write.write(&[1]);
                drop(write);
                process::exit(1);
            } else {
                println!("redoxfs: no disk image provided");
                usage();
            }
        } else if pid > 0 {
            drop(write);

            let mut res = [0];
            read.read(&mut res).unwrap();

            process::exit(res[0] as i32);
        } else {
            panic!("redoxfs: failed to fork");
        }
    } else {
        panic!("redoxfs: failed to create pipe");
    }
}
