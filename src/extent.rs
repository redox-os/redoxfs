use std::cmp::min;

use BLOCK_SIZE;

pub struct BlockIter {
    block: u64,
    length: u64,
    i: u64
}

impl Iterator<> for BlockIter {
    type Item = (u64, u64);
    fn next(&mut self) -> Option<Self::Item> {
        if self.i < (self.length + BLOCK_SIZE - 1)/BLOCK_SIZE {
            let ret = Some((self.block + self.i, min(BLOCK_SIZE, self.length - self.i * BLOCK_SIZE)));
            self.i += 1;
            ret
        } else {
            None
        }
    }
}

/// A disk extent, [wikipedia](https://en.wikipedia.org/wiki/Extent_(file_systems))
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
pub struct Extent {
    pub block: u64,
    pub length: u64,
}

impl Extent {
    pub fn default() -> Extent {
        Extent {
            block: 0,
            length: 0
        }
    }

    pub fn new(block: u64, length: u64) -> Extent {
        Extent {
            block: block,
            length: length
        }
    }

    pub fn blocks(&self) -> BlockIter {
        BlockIter {
            block: self.block,
            length: self.length,
            i: 0
        }
    }
}
