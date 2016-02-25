/// A disk extent
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
pub struct Extent {
    pub block: u64,
    pub length: u64,
}

impl Extent {
    pub fn new(block: u64, length: u64) -> Extent {
        Extent {
            block: block,
            length: length
        }
    }
}
