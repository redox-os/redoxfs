extern crate redoxfs;
extern crate syscall;
extern crate uuid;

use std::{env, fs, process};
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redoxfs::{BLOCK_SIZE, Disk, DiskFile, Extent, FileSystem, Node};
use uuid::Uuid;

fn syscall_err(err: syscall::Error) -> io::Error {
    io::Error::from_raw_os_error(err.errno)
}

fn archive_at<D: Disk, P: AsRef<Path>>(fs: &mut FileSystem<D>, parent_path: P, ctime: &Duration, parent_block: u64) -> io::Result<()> {
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
            archive_at(fs, path, ctime, node.0)?;
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


fn archive<D: Disk, P: AsRef<Path>>(fs: &mut FileSystem<D>, parent_path: P, ctime: &Duration) -> io::Result<u64> {
    let root_block = fs.header.1.root;
    archive_at(fs, parent_path, ctime, root_block)?;

    let free_block = fs.header.1.free;
    let mut free = fs.node(free_block).map_err(syscall_err)?;
    let end_block = free.1.extents[0].block;
    free.1.extents[0] = Extent::default();
    fs.write_at(free.0, &free.1).map_err(syscall_err)?;

    fs.header.1.size = end_block;
    let header = fs.header;
    fs.write_at(header.0, &header.1).map_err(syscall_err)?;

    Ok(end_block * BLOCK_SIZE)
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

    let ctime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    match FileSystem::create_reserved(disk, &bootloader, ctime.as_secs(), ctime.subsec_nanos()) {
        Ok(mut fs) => {
            let size = match archive(&mut fs, &folder_path, &ctime) {
                Ok(ok) => ok,
                Err(err) => {
                    println!("redoxfs-ar: failed to archive {}: {}", folder_path, err);
                    process::exit(1);
                }
            };

            if let Err(err) = fs.disk.file.set_len(size) {
                println!("redoxfs-ar: failed to truncate {} to {}: {}", disk_path, size, err);
                process::exit(1);
            }

            let uuid = Uuid::from_bytes(&fs.header.1.uuid).unwrap();
            println!(
                "redoxfs-ar: created filesystem on {}, reserved {} blocks, size {} MB, uuid {}",
                disk_path,
                fs.block,
                fs.header.1.size/1000/1000,
                uuid.hyphenated()
            );
        },
        Err(err) => {
            println!("redoxfs-ar: failed to create filesystem on {}: {}", disk_path, err);
            process::exit(1);
        }
    };
}
