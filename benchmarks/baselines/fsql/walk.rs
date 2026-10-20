// Traversal source: kjanat/fsql@d5ac9c80a2c5d8322d9ae096d6b0d860d73a4d4f,
// crates/fsql/src/walk.rs. Imports redirected to a minimal row shim; original
// tests omitted. This measures the original walker, not SQL evaluation or
// output formatting.
use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use rustix::fs::{AtFlags, CWD, Dir, Mode, OFlags, StatxFlags};

use super::fsql_baseline_row::{Entry, Kind, Shared};
use super::fsql_baseline_row::{Error, Result};

const DIR_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

#[derive(Debug, Clone, Default)]
pub struct WalkOptions {
    pub max_depth: Option<u32>,
    pub one_filesystem: bool,
    pub initial_depth: u32,
}

struct Frame {
    fd: Arc<OwnedFd>,
    path: PathBuf,
    depth: u32,
    entries: Dir,
}

pub struct Walker {
    shared: Rc<Shared>,
    options: WalkOptions,
    root_mount: Option<u64>,
    pending: VecDeque<Result<Entry>>,
    stack: Vec<Frame>,
}

pub fn c_name(name: &std::ffi::OsStr, path: &Path) -> Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| Error::Io { path: path.to_path_buf(), source: std::io::Error::other("path contains a NUL byte") })
}

pub fn open_chain(directory: &Path) -> Result<OwnedFd> {
    let mut fd = open_dir(CWD, c"/", Path::new("/"))?;
    let mut opened = PathBuf::from("/");
    for component in directory.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        opened.push(part);
        let c_part = c_name(part, &opened)?;
        fd = open_dir(&fd, &c_part, &opened)?;
    }
    Ok(fd)
}

pub fn open_root(root: &Path) -> Result<(Arc<OwnedFd>, CString, PathBuf)> {
    let canonical = std::fs::canonicalize(root).map_err(|source| Error::Io { path: root.to_path_buf(), source })?;
    let (parent, name) = match (canonical.parent(), canonical.file_name()) {
        (Some(parent), Some(name)) => (parent.to_path_buf(), c_name(name, &canonical)?),
        _ => (canonical.clone(), c".".to_owned()),
    };
    let fd = open_chain(&parent)?;
    Ok((Arc::new(fd), name, canonical))
}

fn open_dir(dirfd: impl rustix::fd::AsFd, name: &CStr, path: &Path) -> Result<OwnedFd> {
    rustix::fs::openat(dirfd, name, DIR_FLAGS, Mode::empty())
        .map_err(|errno| Error::Io { path: path.to_path_buf(), source: std::io::Error::from(errno) })
}

impl Walker {
    pub fn new(root: &Path, options: WalkOptions) -> Result<Self> {
        let shared = Shared::new();
        let (parent, name, canonical) = open_root(root)?;
        let root_entry = Entry::new(shared.clone(), parent, name, canonical, options.initial_depth, Kind::Dir);
        let root_mount = if options.one_filesystem { root_entry.mount_id()? } else { None };
        let mut walker = Self { shared, options, root_mount, pending: VecDeque::new(), stack: Vec::new() };
        walker.descend(&root_entry);
        walker.pending.push_back(Ok(root_entry));
        Ok(walker)
    }

    fn descend(&mut self, entry: &Entry) {
        if let Some(max) = self.options.max_depth
            && entry.depth() >= max
        {
            return;
        }
        if self.root_mount.is_some() {
            match entry.mount_id() {
                Ok(mount) if mount != self.root_mount => return,
                Ok(_) => {}
                Err(error) => {
                    self.pending.push_back(Err(error));
                    return;
                }
            }
        }
        if !super::delayed::delay().is_zero() {
            std::thread::sleep(super::delayed::delay());
        }
        let fd = match open_dir(entry.dir(), entry.name_c(), entry.path()) {
            Ok(fd) => Arc::new(fd),
            Err(error) => {
                self.pending.push_back(Err(error));
                return;
            }
        };
        if self.root_mount.is_some() {
            let stat = rustix::fs::statx(&fd, c"", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID);
            match stat {
                Ok(stat)
                    if stat.stx_mask & StatxFlags::MNT_ID.bits() != 0 && Some(stat.stx_mnt_id) != self.root_mount =>
                {
                    return;
                }
                _ => {}
            }
        }
        let entries = match Dir::read_from(&fd) {
            Ok(entries) => entries,
            Err(errno) => {
                self.pending.push_back(Err(Error::Io {
                    path: entry.path().to_path_buf(),
                    source: std::io::Error::from(errno),
                }));
                return;
            }
        };
        self.stack.push(Frame { fd, path: entry.path().to_path_buf(), depth: entry.depth() + 1, entries });
    }

    fn next_from_stack(&mut self) -> Option<Result<Entry>> {
        loop {
            let frame = self.stack.last_mut()?;
            let Some(dirent) = frame.entries.next() else {
                self.stack.pop();
                continue;
            };
            let dirent = match dirent {
                Ok(dirent) => dirent,
                Err(errno) => {
                    let path = frame.path.clone();
                    self.stack.pop();
                    return Some(Err(Error::Io { path, source: std::io::Error::from(errno) }));
                }
            };
            let name = dirent.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            let path = frame.path.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
            let entry = Entry::new(
                self.shared.clone(),
                frame.fd.clone(),
                name.to_owned(),
                path,
                frame.depth,
                Kind::from_file_type(dirent.file_type()),
            );
            match entry.is_dir() {
                Ok(true) => self.descend(&entry),
                Ok(false) => {}
                Err(error) => {
                    self.pending.push_back(Err(error));
                    continue;
                }
            }
            return Some(Ok(entry));
        }
    }
}

impl Iterator for Walker {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(pending) = self.pending.pop_front() {
            return Some(pending);
        }
        self.next_from_stack()
    }
}
