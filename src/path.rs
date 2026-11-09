//! This module validates root-relative paths and derives their case-folded
//! comparison keys.
//!
//! A [`RelativePath`] keeps the display casing of every component. A
//! [`PathKey`] folds those components under a [`CaseSensitivity`] rule
//! and is the comparison key (RFC §14.1). Snapshots index entries by
//! [`PathKey`] and report paths as [`RelativePath`].

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// `CaseSensitivity` states how one directory compares the names of its
/// children.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CaseSensitivity {
    /// The directory compares names byte for byte.
    Sensitive,
    /// The directory lowercases every UTF-8 name before it compares names.
    ///
    /// The directory compares a name byte for byte when the name is not
    /// valid UTF-8.
    Insensitive,
}

/// `PathError` explains why this module rejected a path or component (RFC
/// §14.1, §20).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathError {
    /// The path has a root or a platform prefix.
    Absolute(PathBuf),
    /// A `..` component climbs above the root.
    EscapesRoot(PathBuf),
    /// A component is empty, `.` or `..`, or it contains `/` or NUL.
    ///
    /// On Windows a component with `\` is also invalid.
    InvalidComponent(OsString),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::Absolute(p) => write!(f, "absolute path {}", p.display()),
            PathError::EscapesRoot(p) => write!(f, "path {} escapes the root", p.display()),
            PathError::InvalidComponent(c) => write!(f, "invalid path component {:?}", c),
        }
    }
}

impl std::error::Error for PathError {}

/// `RelativePath` names a location below the tree root as normalized, validated
/// components.
///
/// The empty path names the root and displays as `.`. The ordering
/// compares components in turn and places every directory directly before
/// its descendants. Each component keeps its original bytes, including the
/// bytes of a name that is not valid Unicode (RFC §20). Clones share
/// storage.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelativePath {
    components: Arc<[OsString]>,
}

impl RelativePath {
    /// `root` returns the path of the tree root.
    pub fn root() -> Self {
        RelativePath { components: Arc::from(Vec::new()) }
    }

    /// `parse` parses and normalizes a relative path.
    ///
    /// It drops `.` components, and each `..` removes the preceding
    /// component.
    ///
    /// # Errors
    ///
    /// `parse` returns [`PathError::Absolute`] for a rooted or prefixed
    /// path and [`PathError::EscapesRoot`] when `..` climbs above the root.
    /// It returns [`PathError::InvalidComponent`] when [`validate_name`]
    /// rejects a component.
    pub fn parse(path: impl AsRef<Path>) -> Result<Self, PathError> {
        let path = path.as_ref();
        let mut components: Vec<OsString> = Vec::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(name) => {
                    validate_name(name)?;
                    components.push(name.to_os_string());
                }
                Component::ParentDir => {
                    if components.pop().is_none() {
                        return Err(PathError::EscapesRoot(path.to_path_buf()));
                    }
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(PathError::Absolute(path.to_path_buf()));
                }
            }
        }
        Ok(RelativePath { components: Arc::from(components) })
    }

    /// `components` returns the components from the root downward.
    pub fn components(&self) -> &[OsString] {
        &self.components
    }

    /// `depth` returns the number of components; the root has depth 0.
    pub fn depth(&self) -> usize {
        self.components.len()
    }

    /// `is_root` reports whether this path names the root.
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// `file_name` returns the last component, or `None` for the root.
    pub fn file_name(&self) -> Option<&OsStr> {
        self.components.last().map(|c| c.as_os_str())
    }

    /// `parent` returns the containing directory, or `None` for the root.
    pub fn parent(&self) -> Option<RelativePath> {
        self.components.split_last().map(|(_, rest)| RelativePath { components: Arc::from(rest.to_vec()) })
    }

    /// `join` appends one component.
    ///
    /// # Errors
    ///
    /// `join` returns [`PathError::InvalidComponent`] when
    /// [`validate_name`] rejects `name`.
    pub fn join(&self, name: &OsStr) -> Result<RelativePath, PathError> {
        validate_name(name)?;
        Ok(self.joined(name))
    }

    pub(crate) fn joined(&self, name: &OsStr) -> RelativePath {
        let mut components = self.components.to_vec();
        components.push(name.to_os_string());
        RelativePath { components: Arc::from(components) }
    }

    /// `starts_with` reports whether `prefix` equals this path or one of its
    /// ancestors.
    ///
    /// It compares components byte for byte.
    pub fn starts_with(&self, prefix: &RelativePath) -> bool {
        self.components.len() >= prefix.components.len()
            && self.components[..prefix.components.len()] == prefix.components[..]
    }

    /// `rebase` replaces the leading `from` components with `to`.
    ///
    /// It returns `None` when this path does not start with `from`.
    pub fn rebase(&self, from: &RelativePath, to: &RelativePath) -> Option<RelativePath> {
        if !self.starts_with(from) {
            return None;
        }
        let mut components = to.components.to_vec();
        components.extend_from_slice(&self.components[from.components.len()..]);
        Some(RelativePath { components: Arc::from(components) })
    }

    /// `to_path_buf` converts this path to a platform relative path.
    ///
    /// The root becomes an empty path.
    pub fn to_path_buf(&self) -> PathBuf {
        let mut out = PathBuf::new();
        for c in self.components.iter() {
            out.push(c);
        }
        out
    }

    /// `under` resolves this path against `root`.
    pub fn under(&self, root: &Path) -> PathBuf {
        let mut out = root.to_path_buf();
        for c in self.components.iter() {
            out.push(c);
        }
        out
    }

    /// `key` folds every component under the single rule `case`.
    ///
    /// Directories can declare their own case rule. For those trees,
    /// [`crate::snapshot::Snapshot::key`] derives the correct key.
    pub fn key(&self, case: CaseSensitivity) -> PathKey {
        match case {
            CaseSensitivity::Sensitive => PathKey { folded: self.clone() },
            CaseSensitivity::Insensitive => {
                let components: Vec<OsString> = self.components.iter().map(|c| fold_component(c)).collect();
                PathKey { folded: RelativePath { components: Arc::from(components) } }
            }
        }
    }
}

fn fold_component(name: &OsStr) -> OsString {
    match name.to_str() {
        Some(s) => OsString::from(s.to_lowercase()),
        None => name.to_os_string(),
    }
}

/// `validate_name` checks that `name` is a valid path component.
///
/// # Errors
///
/// `validate_name` returns [`PathError::InvalidComponent`] when `name` is
/// empty, `.` or `..`, or when it contains `/` or NUL. On Windows it also
/// rejects `\`.
pub fn validate_name(name: &OsStr) -> Result<(), PathError> {
    let bytes = name.as_encoded_bytes();
    let invalid = bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.iter().any(|b| *b == b'/' || *b == 0 || (cfg!(windows) && *b == b'\\'));
    if invalid {
        return Err(PathError::InvalidComponent(name.to_os_string()));
    }
    Ok(())
}

impl fmt::Display for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.components.is_empty() {
            return f.write_str(".");
        }
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                f.write_str("/")?;
            }
            f.write_str(&c.to_string_lossy())?;
        }
        Ok(())
    }
}

impl fmt::Debug for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_string())
    }
}

impl std::str::FromStr for RelativePath {
    type Err = PathError;

    fn from_str(value: &str) -> Result<Self, PathError> {
        RelativePath::parse(value)
    }
}

impl TryFrom<&Path> for RelativePath {
    type Error = PathError;

    fn try_from(value: &Path) -> Result<Self, PathError> {
        RelativePath::parse(value)
    }
}

/// `PathKey` is the comparison key of a path.
///
/// `PathKey` folds each component under the case rule of its directory. Two
/// paths that name the same entry produce equal keys. Keys order like
/// [`RelativePath`] and place a directory directly before its
/// descendants.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathKey {
    folded: RelativePath,
}

impl PathKey {
    /// `root` returns the key of the tree root.
    pub fn root() -> PathKey {
        PathKey { folded: RelativePath::root() }
    }

    /// `depth` returns the number of components; the root has depth 0.
    pub fn depth(&self) -> usize {
        self.folded.depth()
    }

    /// `is_root` reports whether this key names the root.
    pub fn is_root(&self) -> bool {
        self.folded.is_root()
    }

    /// `parent` returns the key of the containing directory, or `None` for the
    /// root.
    pub fn parent(&self) -> Option<PathKey> {
        self.folded.parent().map(|folded| PathKey { folded })
    }

    /// `starts_with` reports whether `prefix` equals this key or one of its
    /// ancestors.
    pub fn starts_with(&self, prefix: &PathKey) -> bool {
        self.folded.starts_with(&prefix.folded)
    }

    /// `child` folds `name` under `case` and appends it.
    ///
    /// The caller passes the case rule of this key's directory as `case`.
    ///
    /// # Errors
    ///
    /// `child` returns [`PathError::InvalidComponent`] when
    /// [`validate_name`] rejects `name`.
    pub fn child(&self, name: &OsStr, case: CaseSensitivity) -> Result<PathKey, PathError> {
        validate_name(name)?;
        Ok(self.descend(name, case))
    }

    /// `descend` folds `name` under `case` and appends it without validation.
    ///
    /// The caller must pass a component of a [`RelativePath`] or a name
    /// that passed [`validate_name`].
    pub fn descend(&self, name: &OsStr, case: CaseSensitivity) -> PathKey {
        let folded_name = match case {
            CaseSensitivity::Sensitive => name.to_os_string(),
            CaseSensitivity::Insensitive => fold_component(name),
        };
        let mut components = self.folded.components.to_vec();
        components.push(folded_name);
        PathKey { folded: RelativePath { components: Arc::from(components) } }
    }
}

impl fmt::Debug for PathKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key({:?})", self.folded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes() {
        let p = RelativePath::parse("a/./b/../c").expect("valid");
        assert_eq!(p.to_string(), "a/c");
        assert_eq!(p.depth(), 2);
        assert_eq!(p.parent().expect("parent").to_string(), "a");
    }

    #[test]
    fn rejects_escapes_and_absolute() {
        assert!(matches!(RelativePath::parse("../x"), Err(PathError::EscapesRoot(_))));
        assert!(matches!(RelativePath::parse("a/../../x"), Err(PathError::EscapesRoot(_))));
        assert!(matches!(RelativePath::parse("/etc"), Err(PathError::Absolute(_))));
    }

    #[test]
    fn folds_case() {
        let a = RelativePath::parse("Foo/Bar").expect("valid");
        let b = RelativePath::parse("foo/bar").expect("valid");
        assert_ne!(a.key(CaseSensitivity::Sensitive), b.key(CaseSensitivity::Sensitive));
        assert_eq!(a.key(CaseSensitivity::Insensitive), b.key(CaseSensitivity::Insensitive));
    }

    #[test]
    fn orders_depth_first() {
        let mut paths: Vec<RelativePath> =
            ["a/c", "a/b/x", "a/b", "b", "a"].iter().map(|p| RelativePath::parse(p).expect("valid")).collect();
        paths.sort();
        let rendered: Vec<String> = paths.iter().map(|p| p.to_string()).collect();
        assert_eq!(rendered, ["a", "a/b", "a/b/x", "a/c", "b"]);
    }
}
