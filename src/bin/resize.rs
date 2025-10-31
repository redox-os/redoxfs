use std::{env, process};

use humansize::{format_size, BINARY, DECIMAL};
use redoxfs::{BlockAddr, BlockMeta, Disk, DiskFile, FileSystem};
use uuid::Uuid;

fn resize<D: Disk>(fs: &mut FileSystem<D>, size_arg: String) -> Result<(), String> {
    let disk_size = fs
        .disk
        .size()
        .map_err(|err| format!("failed to read disk size: {}", err))?;

    // Find contiguous free region
    //TODO: better error management
    let mut last_free = None;
    let mut last_end = 0;
    fs.tx(|tx| {
        let mut alloc_ptr = tx.header.alloc;
        while !alloc_ptr.is_null() {
            let alloc = tx.read_block(alloc_ptr)?;
            alloc_ptr = alloc.data().prev;
            for entry in alloc.data().entries.iter() {
                let count = entry.count();
                if count <= 0 {
                    continue;
                }
                let end = entry.index() + count as u64;
                if end > last_end {
                    last_free = Some(*entry);
                    last_end = end;
                }
            }
        }
        Ok(())
    })
    .map_err(|err| format!("failed to read alloc log: {}", err))?;

    let old_size = fs.header.size();
    let min_size = if let Some(entry) = last_free {
        entry.index() * redoxfs::BLOCK_SIZE
    } else {
        old_size
    };
    let max_size = disk_size - (fs.block * redoxfs::BLOCK_SIZE);

    let new_size = match size_arg.to_lowercase().as_str() {
        "min" | "minimum" => min_size,
        "" | "max" | "maximum" => max_size,
        _ => match parse_size::parse_size(&size_arg) {
            Ok(new_size) => {
                if new_size < min_size {
                    return Err(format!(
                        "requested size {} is smaller than {} by {}",
                        new_size,
                        min_size,
                        min_size - new_size
                    ));
                }

                if new_size > max_size {
                    return Err(format!(
                        "requested size {} is larger than {} by {}",
                        new_size,
                        max_size,
                        new_size - max_size
                    ));
                }

                new_size
            }
            Err(err) => {
                return Err(format!(
                    "failed to parse size argument {:?}: {}",
                    size_arg, err
                ));
            }
        },
    };

    println!(
        "minimum size: {} ({})",
        format_size(min_size, DECIMAL),
        format_size(min_size, BINARY)
    );
    println!(
        "maximum size: {} ({})",
        format_size(max_size, DECIMAL),
        format_size(max_size, BINARY)
    );
    println!(
        "new size: {} ({})",
        format_size(new_size, DECIMAL),
        format_size(new_size, BINARY)
    );

    let old_blocks = old_size / redoxfs::BLOCK_SIZE;
    let new_blocks = new_size / redoxfs::BLOCK_SIZE;
    let (start, end, shrink) = if new_size == old_size {
        println!("already requested size");
        return Ok(());
    } else if new_size < old_size {
        println!("shrinking by {}", old_size - new_size);
        (new_blocks, old_blocks, true)
    } else {
        println!("growing by {}", new_size - old_size);
        (old_blocks, new_blocks, false)
    };

    // Allocate or deallocate blocks as needed
    unsafe {
        let allocator = fs.allocator_mut();
        for index in start..end {
            if shrink {
                //TODO: replace assert with error?
                let addr = BlockAddr::new(index as u64, BlockMeta::default());
                assert_eq!(allocator.allocate_exact(addr), Some(addr));
            } else {
                let addr = BlockAddr::new(index as u64, BlockMeta::default());
                allocator.deallocate(addr);
            }
        }
    }

    fs.tx(|tx| {
        // Update header
        tx.header.size = new_size.into();
        tx.header_changed = true;

        // Sync with squash
        tx.sync(true)?;

        Ok(())
    })
    .map_err(|err| format!("transaction failed: {}", err))
}

fn main() {
    env_logger::init();

    let mut args = env::args().skip(1);

    let disk_path = if let Some(path) = args.next() {
        path
    } else {
        eprintln!("redoxfs-resize: no new disk image provided");
        eprintln!("redoxfs-resize NEW-DISK [SIZE]");
        process::exit(1);
    };

    let size_arg = args.next().unwrap_or_default();

    let disk = match DiskFile::open(&disk_path) {
        Ok(disk) => disk,
        Err(err) => {
            eprintln!(
                "redoxfs-resize: failed to open disk image {}: {}",
                disk_path, err
            );
            process::exit(1);
        }
    };

    let mut fs = match FileSystem::open(disk, None, None, true) {
        Ok(fs) => fs,
        Err(err) => {
            eprintln!(
                "redoxfs-resize: failed to open filesystem on {}: {}",
                disk_path, err
            );
            process::exit(1);
        }
    };

    match resize(&mut fs, size_arg) {
        Ok(()) => {}
        Err(err) => {
            eprintln!(
                "redoxfs-resize: failed to resize filesystem on {}: {}",
                disk_path, err
            );
            process::exit(1);
        }
    }

    let uuid = Uuid::from_bytes(fs.header.uuid());
    let size = fs.header.size();
    let free = fs.allocator().free() * redoxfs::BLOCK_SIZE;
    let used = size - free;
    println!("redoxfs-resize: resized filesystem on {}", disk_path);
    println!("\tuuid: {}", uuid.hyphenated());
    println!(
        "\tsize: {} ({})",
        format_size(size, DECIMAL),
        format_size(size, BINARY)
    );
    println!(
        "\tused: {} ({})",
        format_size(used, DECIMAL),
        format_size(used, BINARY)
    );
    println!(
        "\tfree: {} ({})",
        format_size(free, DECIMAL),
        format_size(free, BINARY)
    );
}
