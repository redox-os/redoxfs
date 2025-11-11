use std::time::{Duration, Instant};
use syscall::error::Result;

use crate::{Disk, FileSystem, Transaction};

#[cfg(all(not(target_os = "redox"), not(fuzzing)))]
mod fuse;
#[cfg(all(not(target_os = "redox"), fuzzing))]
pub mod fuse;

#[cfg(not(target_os = "redox"))]
pub use self::fuse::mount;

#[cfg(target_os = "redox")]
mod redox;

#[cfg(target_os = "redox")]
pub use self::redox::mount;

// Wrapper to assist with permanent tx and write caching
pub(crate) struct TxWrapper<'fs, D: Disk> {
    tx: Transaction<'fs, D>,
    // Maximum time between syncs
    sync_interval: Duration,
    // Time for next sync
    sync_time: Option<Instant>,
    // Limit of blocks in write cache
    write_cache_limit: usize,
}

impl<'fs, D: Disk> TxWrapper<'fs, D> {
    pub(crate) fn new(fs: &'fs mut FileSystem<D>) -> Self {
        Self {
            tx: Transaction::new(fs),
            //TODO: make configurable?
            sync_interval: Duration::new(1, 0),
            sync_time: None,
            //TODO: make configurable, make larger after fixing on Redox?
            write_cache_limit: 64,
        }
    }

    //TODO: call this automatically on timeout
    pub(crate) fn maybe_sync(&mut self) -> Result<Option<Instant>> {
        if self.tx.write_cache.len() >= self.write_cache_limit || {
            let now = Instant::now();
            now >= *self
                .sync_time
                .get_or_insert_with(|| now + self.sync_interval)
        } {
            self.tx.sync(false)?;
            self.sync_time = None;
        }

        Ok(self.sync_time)
    }

    pub(crate) fn tx<F: FnOnce(&mut Transaction<'fs, D>) -> Result<T>, T>(
        &mut self,
        f: F,
    ) -> Result<T> {
        //TODO: is it necessary to do this before and after?
        self.maybe_sync()?;
        let t = f(&mut self.tx)?;
        self.maybe_sync()?;
        Ok(t)
    }

    pub(crate) fn commit(mut self, squash: bool) -> Result<()> {
        self.tx.commit(squash)
    }
}
