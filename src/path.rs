use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CaseSensitivity {
    Sensitive,
    Insensitive,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathError {
    Absolute(PathBuf),
    EscapesRoot(PathBuf),
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

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelativePath {
    components: Arc<[OsString]>,
}

impl RelativePath {
    pub fn root() -> Self {
        RelativePath { components: Arc::from(Vec::new()) }
    }

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

    pub fn from_components(components: Vec<OsString>) -> Result<Self, PathError> {
        for name in &components {
            validate_name(name)?;
        }
        Ok(RelativePath { components: Arc::from(components) })
    }

    pub fn components(&self) -> &[OsString] {
        &self.components
    }

    pub fn depth(&self) -> usize {
        self.components.len()
    }

    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    pub fn file_name(&self) -> Option<&OsStr> {
        self.components.last().map(|c| c.as_os_str())
    }

    pub fn parent(&self) -> Option<RelativePath> {
        self.components.split_last().map(|(_, rest)| RelativePath { components: Arc::from(rest.to_vec()) })
    }

    pub fn join(&self, name: &OsStr) -> Result<RelativePath, PathError> {
        validate_name(name)?;
        let mut components = self.components.to_vec();
        components.push(name.to_os_string());
        Ok(RelativePath { components: Arc::from(components) })
    }

    pub fn starts_with(&self, prefix: &RelativePath) -> bool {
        self.components.len() >= prefix.components.len()
            && self.components[..prefix.components.len()] == prefix.components[..]
    }

    pub fn rebase(&self, from: &RelativePath, to: &RelativePath) -> Option<RelativePath> {
        if !self.starts_with(from) {
            return None;
        }
        let mut components = to.components.to_vec();
        components.extend_from_slice(&self.components[from.components.len()..]);
        Some(RelativePath { components: Arc::from(components) })
    }

    pub fn to_path_buf(&self) -> PathBuf {
        let mut out = PathBuf::new();
        for c in self.components.iter() {
            out.push(c);
        }
        out
    }

    pub fn under(&self, root: &Path) -> PathBuf {
        let mut out = root.to_path_buf();
        for c in self.components.iter() {
            out.push(c);
        }
        out
    }

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

impl TryFrom<&str> for RelativePath {
    type Error = PathError;

    fn try_from(value: &str) -> Result<Self, PathError> {
        RelativePath::parse(value)
    }
}

impl TryFrom<&Path> for RelativePath {
    type Error = PathError;

    fn try_from(value: &Path) -> Result<Self, PathError> {
        RelativePath::parse(value)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathKey {
    folded: RelativePath,
}

impl PathKey {
    pub fn depth(&self) -> usize {
        self.folded.depth()
    }

    pub fn is_root(&self) -> bool {
        self.folded.is_root()
    }

    pub fn parent(&self) -> Option<PathKey> {
        self.folded.parent().map(|folded| PathKey { folded })
    }

    pub fn starts_with(&self, prefix: &PathKey) -> bool {
        self.folded.starts_with(&prefix.folded)
    }

    pub fn folded(&self) -> &RelativePath {
        &self.folded
    }

    pub fn child(&self, name: &OsStr, case: CaseSensitivity) -> Result<PathKey, PathError> {
        let folded_name = match case {
            CaseSensitivity::Sensitive => name.to_os_string(),
            CaseSensitivity::Insensitive => fold_component(name),
        };
        Ok(PathKey { folded: self.folded.join(&folded_name)? })
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
