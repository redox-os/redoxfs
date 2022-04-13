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

pub struct DiskCache<T> {
    inner: T,
    cache: HashMap<u64, [u8; BLOCK_SIZE as usize]>,
    order: VecDeque<u64>,
    size: usize,
}

impl<T: Disk> DiskCache<T> {
    pub fn new(inner: T) -> Self {
        DiskCache {
            inner,
            cache: HashMap::new(),
            order: VecDeque::new(),
            size: 16 * 1024 * 1024 / BLOCK_SIZE as usize, // 16 MB cache
        }
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

impl<T: Disk> Disk for DiskCache<T> {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        // println!("Cache read at {}", block);

        let mut read = 0;
        let mut failed = false;
        for i in 0..(buffer.len() + BLOCK_SIZE as usize - 1) / (BLOCK_SIZE as usize) {
            let block_i = block + i as u64;

            let buffer_i = i * BLOCK_SIZE as usize;
            let buffer_j = cmp::min(buffer_i + BLOCK_SIZE as usize, buffer.len());
            let buffer_slice = &mut buffer[buffer_i..buffer_j];

            if let Some(cache_buf) = self.cache.get_mut(&block_i) {
                read += copy_memory(cache_buf, buffer_slice);
            } else {
                failed = true;
                break;
            }
        }

        if failed {
            self.inner.read_at(block, buffer)?;

            read = 0;
            for i in 0..(buffer.len() + BLOCK_SIZE as usize - 1) / (BLOCK_SIZE as usize) {
                let block_i = block + i as u64;

                let buffer_i = i * BLOCK_SIZE as usize;
                let buffer_j = cmp::min(buffer_i + BLOCK_SIZE as usize, buffer.len());
                let buffer_slice = &buffer[buffer_i..buffer_j];

                let mut cache_buf = [0; BLOCK_SIZE as usize];
                read += copy_memory(buffer_slice, &mut cache_buf);
                self.insert(block_i, cache_buf);
            }
        }

        Ok(read)
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        //TODO: Write only blocks that have changed
        // println!("Cache write at {}", block);

        self.inner.write_at(block, buffer)?;

        let mut written = 0;
        for i in 0..(buffer.len() + BLOCK_SIZE as usize - 1) / (BLOCK_SIZE as usize) {
            let block_i = block + i as u64;

            let buffer_i = i * BLOCK_SIZE as usize;
            let buffer_j = cmp::min(buffer_i + BLOCK_SIZE as usize, buffer.len());
            let buffer_slice = &buffer[buffer_i..buffer_j];

            let mut cache_buf = [0; BLOCK_SIZE as usize];
            written += copy_memory(buffer_slice, &mut cache_buf);
            self.insert(block_i, cache_buf);
        }

        Ok(written)
    }

    fn size(&mut self) -> Result<u64> {
        self.inner.size()
    }
}
