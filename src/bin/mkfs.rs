extern crate redoxfs;
extern crate uuid;

use std::io::Read;
use std::{env, fs, io, process, time};

use redoxfs::{DiskFile, FileSystem};
use termion::input::TermRead;
use uuid::Uuid;

fn usage() -> ! {
    eprintln!("redoxfs-mkfs [--encrypt] DISK [BOOTLOADER]");
    process::exit(1);
}

fn main() {
    env_logger::init();

    let mut encrypt = false;
    let mut disk_path_opt = None;
    let mut bootloader_path_opt = None;
    for arg in env::args().skip(1) {
        if arg == "--encrypt" {
            encrypt = true;
        } else if disk_path_opt.is_none() {
            disk_path_opt = Some(arg);
        } else if bootloader_path_opt.is_none() {
            bootloader_path_opt = Some(arg);
        } else {
            eprintln!("redoxfs-mkfs: too many arguments provided");
            usage();
        }
    }

    let disk_path = if let Some(path) = disk_path_opt {
        path
    } else {
        eprintln!("redoxfs-mkfs: no disk image provided");
        usage();
    };

    let disk = match DiskFile::open(&disk_path) {
        Ok(disk) => disk,
        Err(err) => {
            eprintln!("redoxfs-mkfs: failed to open image {}: {}", disk_path, err);
            process::exit(1);
        }
    };

    let mut bootloader = vec![];
    if let Some(bootloader_path) = bootloader_path_opt {
        match fs::File::open(&bootloader_path) {
            Ok(mut file) => match file.read_to_end(&mut bootloader) {
                Ok(_) => (),
                Err(err) => {
                    eprintln!(
                        "redoxfs-mkfs: failed to read bootloader {}: {}",
                        bootloader_path, err
                    );
                    process::exit(1);
                }
            },
            Err(err) => {
                eprintln!(
                    "redoxfs-mkfs: failed to open bootloader {}: {}",
                    bootloader_path, err
                );
                process::exit(1);
            }
        }
    };

    let password_opt = if encrypt {
        eprint!("redoxfs-mkfs: password: ");

        let password = io::stdin()
            .read_passwd(&mut io::stderr())
            .unwrap()
            .unwrap_or(String::new());

        eprintln!();

        if password.is_empty() {
            eprintln!("redoxfs-mkfs: empty password, giving up");
            process::exit(1);
        }

        Some(password)
    } else {
        None
    };

    let ctime = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap();
    match FileSystem::create_reserved(
        disk,
        password_opt.as_ref().map(|x| x.as_bytes()),
        &bootloader,
        ctime.as_secs(),
        ctime.subsec_nanos(),
    ) {
        Ok(filesystem) => {
            let uuid = Uuid::from_bytes(&filesystem.header.uuid()).unwrap();
            eprintln!(
                "redoxfs-mkfs: created filesystem on {}, reserved {} blocks, size {} MB, uuid {}",
                disk_path,
                filesystem.block,
                filesystem.header.size() / 1000 / 1000,
                uuid.hyphenated()
            );
        }
        Err(err) => {
            eprintln!(
                "redoxfs-mkfs: failed to create filesystem on {}: {}",
                disk_path, err
            );
            process::exit(1);
        }
    }
}
