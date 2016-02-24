/// A disk extent
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
pub struct Extent {
    pub block: u64,
    pub length: u64,
}
