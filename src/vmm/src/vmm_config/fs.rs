#[derive(Clone, Debug)]
pub struct FsDeviceConfig {
    pub fs_id: String,
    pub shared_dir: String,
    pub shm_size: Option<usize>,
    pub allow_root_dir_delete: bool,
    pub read_only: bool,
    /// Only this VM changes the shared directory while it runs, so the guest
    /// may cache its metadata, names, listings and data without revalidating.
    pub exclusive: bool,
    /// The guest may also cache writes (FUSE writeback). Only honoured for a
    /// writable exclusive share; host readers then miss unflushed data.
    pub writeback: bool,
}
