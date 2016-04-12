use std::cmp::min;

pub struct BlockIter {
    block: u64,
    length: u64,
    i: u64
}

impl Iterator<> for BlockIter {
    type Item = (u64, usize);
    fn next(&mut self) -> Option<Self::Item> {
        if self.i < (self.length + 511)/512 {
            let ret = Some((self.block + self.i, min(512, self.length - self.i * 512) as usize));
            self.i += 1;
            ret
        } else {
            None
        }
    }
}

/// A disk extent
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
