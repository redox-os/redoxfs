use crate::{Disk, FileSystem, Node, Transaction, TreePtr};

//TODO: handle hard links
async fn clone_at<'a, 'b, D: Disk, E: Disk, F: FnMut(u64)>(
    tx_old: &mut Transaction<'a, D>,
    parent_ptr_old: TreePtr<Node>,
    tx: &mut Transaction<'b, E>,
    parent_ptr: TreePtr<Node>,
    buf: &mut [u8],
    progress: &mut F,
) -> syscall::Result<()> {
    let mut entries = Vec::new();
    tx_old.child_nodes(parent_ptr_old, &mut entries).await?;
    for entry in entries {
        //TODO: return error instead?
        let Some(name) = entry.name() else {
            continue;
        };
        let node_ptr_old = entry.node_ptr();
        let node_old = tx_old.read_tree(node_ptr_old).await?;

        //TODO: this slows down the clone, but Redox has issues without this (Linux is fine)
        tx.sync_if_cache_sized(64).await?;

        let node_ptr = {
            let mode = node_old.data().mode();
            let (ctime, ctime_nsec) = node_old.data().ctime();
            let (mtime, mtime_nsec) = node_old.data().mtime();
            let mut node = tx
                .create_node(parent_ptr, &name, mode, ctime, ctime_nsec)
                .await?;
            node.data_mut().set_uid(node_old.data().uid());
            node.data_mut().set_gid(node_old.data().gid());
            node.data_mut().set_mtime(mtime, mtime_nsec);

            if !node_old.data().is_dir() {
                let mut offset = 0;
                loop {
                    let count = tx_old.read_node_inner(&node_old, offset, buf).await?;
                    if count == 0 {
                        break;
                    }
                    tx.write_node_inner(&mut node, &mut offset, &buf[..count])
                        .await?;
                }
            }

            let node_ptr = node.ptr();
            tx.sync_tree(node).await?;
            node_ptr
        };

        progress(tx.fs_bytes() - tx.fs_free_bytes());

        if node_old.data().is_dir() {
            Box::pin(clone_at(tx_old, node_ptr_old, tx, node_ptr, buf, progress)).await?;
        }
    }

    Ok(())
}

pub async fn clone<D: Disk, E: Disk, F: FnMut(u64)>(
    fs_old: &mut FileSystem<D>,
    fs: &mut FileSystem<E>,
    mut progress: F,
) -> syscall::Result<()> {
    fs_old
        .tx(async |tx_old| {
            let mut tx = Transaction::new(fs);

            // Clone at root node
            let mut buf = vec![0; 4 * 1024 * 1024];
            clone_at(
                tx_old,
                TreePtr::root(),
                &mut tx,
                TreePtr::root(),
                &mut buf,
                &mut progress,
            )
            .await?;

            // Commit and squash alloc log
            tx.commit(true).await
        })
        .await
}
