extern crate redoxfs;
extern crate syscall;
extern crate uuid;

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, process};

use redoxfs::{clone, DiskFile, FileSystem};
use uuid::Uuid;

fn main() {
    env_logger::init();

    let mut args = env::args().skip(1);

    let disk_path_old = if let Some(path) = args.next() {
        path
    } else {
        println!("redoxfs-clone: no old disk image provided");
        println!("redoxfs-clone NEW-DISK OLD-DISK [BOOTLOADER]");
        process::exit(1);
    };

    let disk_path = if let Some(path) = args.next() {
        path
    } else {
        println!("redoxfs-clone: no new disk image provided");
        println!("redoxfs-clone NEW-DISK OLD-DISK [BOOTLOADER]");
        process::exit(1);
    };

    let bootloader_path_opt = args.next();

    // Open old disk in readonly mode
    let disk_old = match fs::OpenOptions::new()
        .read(true)
        .write(false)
        .open(&disk_path_old)
        .map(DiskFile::from)
    {
        Ok(disk) => disk,
        Err(err) => {
            println!(
                "redoxfs-clone: failed to open old disk image {}: {}",
                disk_path_old, err
            );
            process::exit(1);
        }
    };

    let mut fs_old = match FileSystem::open(disk_old, None, None, false) {
        Ok(fs) => fs,
        Err(err) => {
            println!(
                "redoxfs-clone: failed to open filesystem on {}: {}",
                disk_path_old, err
            );
            process::exit(1);
        }
    };

    let disk = match DiskFile::open(&disk_path) {
        Ok(disk) => disk,
        Err(err) => {
            println!(
                "redoxfs-clone: failed to open new disk image {}: {}",
                disk_path, err
            );
            process::exit(1);
        }
    };

    let mut bootloader = vec![];
    if let Some(bootloader_path) = bootloader_path_opt {
        match fs::File::open(&bootloader_path) {
            Ok(mut file) => match file.read_to_end(&mut bootloader) {
                Ok(_) => (),
                Err(err) => {
                    println!(
                        "redoxfs-clone: failed to read bootloader {}: {}",
                        bootloader_path, err
                    );
                    process::exit(1);
                }
            },
            Err(err) => {
                println!(
                    "redoxfs-clone: failed to open bootloader {}: {}",
                    bootloader_path, err
                );
                process::exit(1);
            }
        }
    };

    let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let mut fs = match FileSystem::create_reserved(
        disk,
        None,
        &bootloader,
        ctime.as_secs(),
        ctime.subsec_nanos(),
    ) {
        Ok(fs) => fs,
        Err(err) => {
            println!(
                "redoxfs-clone: failed to create filesystem on {}: {}",
                disk_path, err
            );
            process::exit(1);
        }
    };

    let size_old = fs_old.header.size();
    let free_old = fs_old.allocator().free() * redoxfs::BLOCK_SIZE;
    let used_old = size_old - free_old;
    let mut last_percent = 0;
    match clone(&mut fs_old, &mut fs, move |used| {
        let percent = (used * 100) / used_old;
        if percent != last_percent {
            eprint!(
                "{}%: {} MB/{} MB\r",
                percent,
                used / 1000 / 1000,
                used_old / 1000 / 1000
            );
            last_percent = percent;
        }
    }) {
        Ok(()) => (),
        Err(err) => {
            println!(
                "redoxfs-clone: failed to clone {} to {}: {}",
                disk_path_old, disk_path, err
            );
            process::exit(1);
        }
    }

    let uuid = Uuid::from_bytes(fs.header.uuid());
    let size = fs.header.size();
    let free = fs.allocator().free() * redoxfs::BLOCK_SIZE;
    let used = size - free;
    println!("redoxfs-clone: created filesystem on {}", disk_path,);
    println!("\treserved: {} blocks", fs.block);
    println!("\tuuid: {}", uuid.hyphenated());
    println!("\tsize: {} MB", size / 1000 / 1000);
    println!("\tused: {} MB", used / 1000 / 1000);
    println!("\tfree: {} MB", free / 1000 / 1000);
}
