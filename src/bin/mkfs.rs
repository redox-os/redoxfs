extern crate redoxfs;
extern crate uuid;

use std::{env, fs, process, time};
use std::io::Read;

use redoxfs::{FileSystem, DiskFile};
use uuid::Uuid;

fn main() {
    let mut args = env::args().skip(1);

    let disk_path = if let Some(path) = args.next() {
        path
    } else {
        println!("redoxfs-mkfs: no disk image provided");
        println!("redoxfs-mkfs DISK [BOOTLOADER]");
        process::exit(1);
    };

    let bootloader_path_opt = args.next();

    let disk = match DiskFile::open(&disk_path) {
        Ok(disk) => disk,
        Err(err) => {
            println!("redoxfs-mkfs: failed to open image {}: {}", disk_path, err);
            process::exit(1);
        }
    };

    let mut bootloader = vec![];
    if let Some(bootloader_path) = bootloader_path_opt {
        match fs::File::open(&bootloader_path) {
            Ok(mut file) => match file.read_to_end(&mut bootloader) {
                Ok(_) => (),
                Err(err) => {
                    println!("redoxfs-mkfs: failed to read bootloader {}: {}", bootloader_path, err);
                    process::exit(1);
                }
            },
            Err(err) => {
                println!("redoxfs-mkfs: failed to open bootloader {}: {}", bootloader_path, err);
                process::exit(1);
            }
        }
    };

    let ctime = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
    match FileSystem::create_reserved(disk, &bootloader, ctime.as_secs(), ctime.subsec_nanos()) {
        Ok(filesystem) => {
            let uuid = Uuid::from_bytes(&filesystem.header.1.uuid).unwrap();
            println!("redoxfs-mkfs: created filesystem on {}, reserved {} blocks, size {} MB, uuid {}", disk_path, filesystem.block, filesystem.header.1.size/1000/1000, uuid.hyphenated());
        },
        Err(err) => {
            println!("redoxfs-mkfs: failed to create filesystem on {}: {}", disk_path, err);
            process::exit(1);
        }
    }
}
