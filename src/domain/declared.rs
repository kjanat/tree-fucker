use std::path::Path;

use super::{Crossing, DomainCapabilities, DomainIdentity, DomainProbe, ProbeError, ProbeResult};
use crate::path::CaseSensitivity;

/// `DeclaredProbe` reports one fixed, adapter-declared domain for every
/// directory (RFC §10.3).
///
/// Protocol-native adapters and tests use it when they already know the
/// domain identity and capabilities. The probe answers without filesystem
/// access. It computes [`super::ProbeResult::crossed`] from the declared
/// identity and the parent result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredProbe {
    identity: DomainIdentity,
    capabilities: DomainCapabilities,
    is_domain_root: bool,
    directory_case: Option<CaseSensitivity>,
}

impl DeclaredProbe {
    /// `new` creates a probe that reports `identity` and `capabilities` for
    /// every directory.
    ///
    /// The probe reports `is_domain_root` unchanged for every directory.
    pub fn new(identity: DomainIdentity, capabilities: DomainCapabilities, is_domain_root: bool) -> DeclaredProbe {
        DeclaredProbe { identity, capabilities, is_domain_root, directory_case: None }
    }

    /// `with_directory_case` sets the per-directory case rule of every report.
    ///
    /// A new probe reports `None` until a caller sets a rule.
    pub fn with_directory_case(self, directory_case: Option<CaseSensitivity>) -> DeclaredProbe {
        DeclaredProbe { directory_case, ..self }
    }

    /// `capabilities` returns the declared capabilities.
    pub fn capabilities(&self) -> &DomainCapabilities {
        &self.capabilities
    }
}

impl DomainProbe for DeclaredProbe {
    fn probe(&self, _directory: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, ProbeError> {
        Ok(ProbeResult {
            crossed: Crossing::between(parent, &self.identity),
            identity: self.identity.clone(),
            capabilities: self.capabilities.clone(),
            is_domain_root: self.is_domain_root,
            directory_case: self.directory_case,
        })
    }
}

/// `UnknownProbe` answers Unknown for every directory.
///
/// Every result matches [`super::ProbeResult::unknown`] except the
/// crossing. The probe reports NotCrossed for the tree root and
/// Inconclusive below it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnknownProbe;

impl DomainProbe for UnknownProbe {
    fn probe(&self, _directory: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, ProbeError> {
        Ok(ProbeResult { crossed: Crossing::between(parent, &DomainIdentity::Unknown), ..ProbeResult::unknown() })
    }
}
