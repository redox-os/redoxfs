#![deny(warnings)]
#![cfg_attr(unix, feature(libc))]

#[cfg(unix)]
extern crate libc;

extern crate redoxfs;
extern crate syscall;

use std::env;
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::process;

use cache::Cache;
use image::Image;

pub mod cache;
pub mod image;

#[cfg(unix)]
pub mod fuse;

#[cfg(target_os = "redox")]
pub mod redox;

#[cfg(unix)]
fn fork() -> isize {
    unsafe { libc::fork() as isize }
}

#[cfg(unix)]
fn pipe(pipes: &mut [i32; 2]) -> isize {
    unsafe { libc::pipe2(pipes.as_mut_ptr(), 0) as isize }
}

#[cfg(all(unix, target_os = "macos"))]
fn mount<P: AsRef<Path>>(filesystem: redoxfs::FileSystem, mountpoint: &P, mut write: File) {
    use std::io::Write;

    let _ = write.write(&[0]);
    drop(write);

    fuse::mount(fuse::Fuse {
        fs: filesystem
    }, mountpoint, &[
        // One of the uses of this redoxfs fuse wrapper is to populate a filesystem
        // while building the Redox OS kernel. This means that we need to write on
        // a filesystem that belongs to `root`, which in turn means that we need to
        // be `root`, thus that we need to allow `root` to have access.
        OsStr::new("-o"),
        OsStr::new("defer_permissions"),
    ]);
}

#[cfg(all(unix, not(target_os = "macos")))]
fn mount<P: AsRef<Path>>(filesystem: redoxfs::FileSystem, mountpoint: &P, mut write: File) {
    use std::io::Write;

    let _ = write.write(&[0]);
    drop(write);

    fuse::mount(fuse::Fuse {
        fs: filesystem
    }, mountpoint, &[]);
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
                match Image::open(&path).map(|image| Cache::new(image)) {
                    Ok(disk) => match redoxfs::FileSystem::open(Box::new(disk)) {
                        Ok(filesystem) => {
                            println!("redoxfs: opened filesystem {}", path);

                            if let Some(mountpoint) = env::args_os().nth(2) {
                                mount(filesystem, &mountpoint, write);
                                process::exit(0);
                            } else {
                                println!("redoxfs: no mount point provided");
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
