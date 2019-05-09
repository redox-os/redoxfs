extern crate redoxfs;
extern crate syscall;
extern crate uuid;

use std::{env, fs, process, time};
use std::io::{self, Read};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use redoxfs::{Disk, DiskFile, FileSystem, Node};
use uuid::Uuid;

fn syscall_err(err: syscall::Error) -> io::Error {
    io::Error::from_raw_os_error(err.errno)
}

fn archive<D: Disk, P: AsRef<Path>>(fs: &mut FileSystem<D>, parent_block: u64, parent_path: P) -> io::Result<()> {
    for entry_res in fs::read_dir(parent_path)? {
        let entry = entry_res?;

        let name = entry.file_name().into_string().map_err(|_|
            io::Error::new(
                io::ErrorKind::InvalidData,
                "filename is not valid UTF-8"
            )
        )?;
        let path = entry.path();

        let dir = path.is_dir();
        let (mode_type, mode_perm) = if dir {
            (Node::MODE_DIR, 0o755)
        } /* else if flags & O_SYMLINK == O_SYMLINK {
            Node::MODE_SYMLINK
        } */ else {
            (Node::MODE_FILE, 0o644)
        };

        let mode = mode_type | (mode_perm & Node::MODE_PERM);
        let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let mut node = fs.create_node(
            mode,
            &name,
            parent_block,
            ctime.as_secs(),
            ctime.subsec_nanos()
        ).map_err(syscall_err)?;
        node.1.uid = 0;
        node.1.gid = 0;
        fs.write_at(node.0, &node.1).map_err(syscall_err)?;

        if dir {
            archive(fs, node.0, path)?;
        } else {
            let data = fs::read(path)?;
            fs.write_node(
                node.0,
                0,
                &data,
                ctime.as_secs(),
                ctime.subsec_nanos()
            ).map_err(syscall_err)?;
        }
    }

    Ok(())
}

fn main() {
    let mut args = env::args().skip(1);

    let disk_path = if let Some(path) = args.next() {
        path
    } else {
        println!("redoxfs-ar: no disk image provided");
        println!("redoxfs-ar DISK FOLDER [BOOTLOADER]");
        process::exit(1);
    };

    let folder_path = if let Some(path) = args.next() {
        path
    } else {
        println!("redoxfs-ar: no folder provided");
        println!("redoxfs-ar DISK FOLDER [BOOTLOADER]");
        process::exit(1);
    };

    let bootloader_path_opt = args.next();

    let disk = match DiskFile::open(&disk_path) {
        Ok(disk) => disk,
        Err(err) => {
            println!("redoxfs-ar: failed to open image {}: {}", disk_path, err);
            process::exit(1);
        }
    };

    let mut bootloader = vec![];
    if let Some(bootloader_path) = bootloader_path_opt {
        match fs::File::open(&bootloader_path) {
            Ok(mut file) => match file.read_to_end(&mut bootloader) {
                Ok(_) => (),
                Err(err) => {
                    println!("redoxfs-ar: failed to read bootloader {}: {}", bootloader_path, err);
                    process::exit(1);
                }
            },
            Err(err) => {
                println!("redoxfs-ar: failed to open bootloader {}: {}", bootloader_path, err);
                process::exit(1);
            }
        }
    };

    let ctime = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
    match FileSystem::create_reserved(disk, &bootloader, ctime.as_secs(), ctime.subsec_nanos()) {
        Ok(mut filesystem) => {
            let root = filesystem.header.1.root;
            if let Err(err) = archive(&mut filesystem, root, &folder_path) {
                println!("redoxfs-ar: failed to archive {}: {}", folder_path, err);
                process::exit(1);
            }

            let uuid = Uuid::from_bytes(&filesystem.header.1.uuid).unwrap();
            println!("redoxfs-ar: created filesystem on {}, reserved {} blocks, size {} MB, uuid {}", disk_path, filesystem.block, filesystem.header.1.size/1000/1000, uuid.hyphenated());
        },
        Err(err) => {
            println!("redoxfs-ar: failed to create filesystem on {}: {}", disk_path, err);
            process::exit(1);
        }
    }
}
