use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::{Disk, FileSystem, Node, Transaction, TreePtr, BLOCK_SIZE};

fn syscall_err(err: syscall::Error) -> io::Error {
    io::Error::from_raw_os_error(err.errno)
}

//TODO: handle hard links
pub fn clone_at<D: Disk, E: Disk>(
    tx_old: &mut Transaction<D>,
    parent_ptr_old: TreePtr<Node>,
    fs: &mut FileSystem<E>,
    parent_ptr: TreePtr<Node>,
    buf: &mut [u8],
) -> syscall::Result<()> {
    let mut entries = Vec::new();
    tx_old.child_nodes(parent_ptr_old, &mut entries)?;
    for entry in entries {
        //TODO: return error instead?
        let Some(name) = entry.name() else {
            continue;
        };
        let node_ptr_old = entry.node_ptr();
        let node_old = tx_old.read_tree(node_ptr_old)?;

        //TODO: doing the whole clone_at inside a single transaction works on Linux but not Redox
        let node_ptr = fs.tx(|tx| {
            let mode = node_old.data().mode();
            let (ctime, ctime_nsec) = node_old.data().ctime();
            let (mtime, mtime_nsec) = node_old.data().mtime();
            let mut node = tx.create_node(parent_ptr, &name, mode, ctime, ctime_nsec)?;
            node.data_mut().set_uid(node_old.data().uid());
            node.data_mut().set_gid(node_old.data().gid());
            node.data_mut().set_mtime(mtime, mtime_nsec);

            if !node_old.data().is_dir() {
                let mut offset = 0;
                loop {
                    let count = tx_old.read_node_inner(&node_old, offset, buf)?;
                    if count == 0 {
                        break;
                    }
                    tx.write_node_inner(&mut node, &mut offset, &buf[..count])?;
                }
            }

            let node_ptr = node.ptr();
            tx.sync_tree(node)?;
            Ok(node_ptr)
        })?;

        if node_old.data().is_dir() {
            clone_at(tx_old, node_ptr_old, fs, node_ptr, buf)?;
        }
    }

    Ok(())
}

pub fn clone<D: Disk, E: Disk>(
    fs_old: &mut FileSystem<D>,
    fs: &mut FileSystem<E>,
) -> syscall::Result<()> {
    fs_old.tx(|tx_old| {
        // Clone at root node
        let mut buf = vec![0; 4 * 1024 * 1024];
        clone_at(tx_old, TreePtr::root(), fs, TreePtr::root(), &mut buf)?;

        // Squash alloc log
        //TODO tx.sync(true)?;

        Ok(())
    })
}
