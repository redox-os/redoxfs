use async_lock::RwLock;
use std::collections::{HashMap, VecDeque};
use std::{cmp, ptr};
use syscall::error::Result;

use crate::disk::Disk;
use crate::BLOCK_SIZE;

fn copy_memory(src: &[u8], dest: &mut [u8]) -> usize {
    let len = cmp::min(src.len(), dest.len());
    unsafe { ptr::copy(src.as_ptr(), dest.as_mut_ptr(), len) };
    len
}

type Block = [u8; BLOCK_SIZE as usize];

struct DiskCacheState {
    cache: HashMap<u64, Block>,
    order: VecDeque<u64>,
    size: usize,
}

impl DiskCacheState {
    pub fn new() -> Self {
        // 16 MB cache
        let size = 16 * 1024 * 1024 / BLOCK_SIZE as usize;
        Self {
            cache: HashMap::with_capacity(size),
            order: VecDeque::with_capacity(size),
            size,
        }
    }

    fn get(&self, i: &u64) -> Option<&Block> {
        self.cache.get(i)
    }

    fn insert(&mut self, i: u64, data: [u8; BLOCK_SIZE as usize]) {
        while self.order.len() >= self.size {
            let removed = self.order.pop_front().unwrap();
            self.cache.remove(&removed);
        }

        self.cache.insert(i, data);
        self.order.push_back(i);
    }
}

pub struct DiskCache<T> {
    inner: T,
    cache: RwLock<DiskCacheState>,
}

impl<T: Disk> DiskCache<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            cache: RwLock::new(DiskCacheState::new()),
        }
    }
}

impl<T: Disk> Disk for DiskCache<T> {
    async unsafe fn read_at(&self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        // println!("Cache read at {}", block);

        let mut read = 0;
        let mut failed = false;
        let cache = self.cache.read().await;
        for i in 0..buffer.len().div_ceil(BLOCK_SIZE as usize) {
            let block_i = block + i as u64;

            let buffer_i = i * BLOCK_SIZE as usize;
            let buffer_j = cmp::min(buffer_i + BLOCK_SIZE as usize, buffer.len());
            let buffer_slice = &mut buffer[buffer_i..buffer_j];

            if let Some(cache_buf) = cache.get(&block_i) {
                read += copy_memory(cache_buf, buffer_slice);
            } else {
                failed = true;
                break;
            }
        }

        drop(cache);

        if failed {
            // Note that we don't hold the cache lock across disk activity
            self.inner.read_at(block, buffer).await?;

            let mut cache = self.cache.write().await;

            read = 0;
            for i in 0..buffer.len().div_ceil(BLOCK_SIZE as usize) {
                let block_i = block + i as u64;

                let buffer_i = i * BLOCK_SIZE as usize;
                let buffer_j = cmp::min(buffer_i + BLOCK_SIZE as usize, buffer.len());
                let buffer_slice = &buffer[buffer_i..buffer_j];

                let mut cache_buf = [0; BLOCK_SIZE as usize];
                read += copy_memory(buffer_slice, &mut cache_buf);
                cache.insert(block_i, cache_buf);
            }
        }

        Ok(read)
    }

    async unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        //TODO: Write only blocks that have changed
        // println!("Cache write at {}", block);

        self.inner.write_at(block, buffer).await?;

        let mut cache = self.cache.write().await;

        let mut written = 0;
        for i in 0..buffer.len().div_ceil(BLOCK_SIZE as usize) {
            let block_i = block + i as u64;

            let buffer_i = i * BLOCK_SIZE as usize;
            let buffer_j = cmp::min(buffer_i + BLOCK_SIZE as usize, buffer.len());
            let buffer_slice = &buffer[buffer_i..buffer_j];

            let mut cache_buf = [0; BLOCK_SIZE as usize];
            written += copy_memory(buffer_slice, &mut cache_buf);
            cache.insert(block_i, cache_buf);
        }

        Ok(written)
    }

    fn size(&mut self) -> Result<u64> {
        self.inner.size()
    }
}
