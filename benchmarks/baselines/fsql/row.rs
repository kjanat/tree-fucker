//! Row shim for the historical walker. Keeps owned paths, names, shared
//! directory descriptors and lazy statx; omits SQL-only column caches.
use std::cell::OnceCell;
use std::ffi::{CStr, CString};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use rustix::fs::{AtFlags, FileType, Statx, StatxFlags};

#[derive(Debug)]
pub enum Error {
    Io { path: PathBuf, source: std::io::Error },
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
pub struct Shared;
impl Shared {
    pub fn new() -> Rc<Self> {
        Rc::new(Self)
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Dir,
    Other,
    Unknown,
}
impl Kind {
    pub fn from_file_type(kind: FileType) -> Self {
        match kind {
            FileType::Directory => Self::Dir,
            FileType::Unknown => Self::Unknown,
            _ => Self::Other,
        }
    }
}
pub struct Entry {
    _shared: Rc<Shared>,
    fd: Arc<OwnedFd>,
    name: CString,
    path: PathBuf,
    depth: u32,
    kind: Kind,
    stat: OnceCell<std::result::Result<Statx, rustix::io::Errno>>,
}
impl Entry {
    pub fn new(shared: Rc<Shared>, fd: Arc<OwnedFd>, name: CString, path: PathBuf, depth: u32, kind: Kind) -> Self {
        Self { _shared: shared, fd, name, path, depth, kind, stat: OnceCell::new() }
    }
    pub fn dir(&self) -> &OwnedFd {
        &self.fd
    }
    pub fn name_c(&self) -> &CStr {
        &self.name
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn depth(&self) -> u32 {
        self.depth
    }
    fn stat(&self) -> Result<&Statx> {
        self.stat
            .get_or_init(|| {
                rustix::fs::statx(
                    &*self.fd,
                    &*self.name,
                    AtFlags::SYMLINK_NOFOLLOW,
                    StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
                )
            })
            .as_ref()
            .map_err(|error| Error::Io { path: self.path.clone(), source: (*error).into() })
    }
    pub fn mount_id(&self) -> Result<Option<u64>> {
        let stat = self.stat()?;
        Ok((stat.stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(stat.stx_mnt_id))
    }
    pub fn is_dir(&self) -> Result<bool> {
        if self.kind != Kind::Unknown {
            return Ok(self.kind == Kind::Dir);
        }
        Ok(FileType::from_raw_mode(u32::from(self.stat()?.stx_mode)) == FileType::Directory)
    }
}
