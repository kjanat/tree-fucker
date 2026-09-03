use std::path::Path;

use super::{Crossing, DomainCapabilities, DomainIdentity, DomainProbe, ProbeError, ProbeResult};
use crate::path::CaseSensitivity;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredProbe {
    identity: DomainIdentity,
    capabilities: DomainCapabilities,
    is_domain_root: bool,
    directory_case: Option<CaseSensitivity>,
}

impl DeclaredProbe {
    pub fn new(identity: DomainIdentity, capabilities: DomainCapabilities, is_domain_root: bool) -> DeclaredProbe {
        DeclaredProbe { identity, capabilities, is_domain_root, directory_case: None }
    }

    pub fn with_directory_case(self, directory_case: Option<CaseSensitivity>) -> DeclaredProbe {
        DeclaredProbe { directory_case, ..self }
    }

    pub fn identity(&self) -> &DomainIdentity {
        &self.identity
    }

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnknownProbe;

impl DomainProbe for UnknownProbe {
    fn probe(&self, _directory: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, ProbeError> {
        Ok(ProbeResult { crossed: Crossing::between(parent, &DomainIdentity::Unknown), ..ProbeResult::unknown() })
    }
}
