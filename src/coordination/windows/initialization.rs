//! Initialize only unpublished state; retain committed debt through reopen.

use std::io::{Read, Seek, SeekFrom, Write};

use super::*;
use crate::coordination::{journal, wire::checksum};

const HEADER: usize = 256;
const MAGIC: &[u8; 8] = b"TFWIN001";
const PREPARING: u8 = 0x5a;
const READY: u8 = 0xa5;

fn encode_id(bytes: &mut [u8], id: Identity) {
    bytes[..8].copy_from_slice(&id.volume.to_le_bytes());
    bytes[8..24].copy_from_slice(&id.file);
}

fn matches_id(bytes: &[u8], id: Identity) -> bool {
    bytes[..8] == id.volume.to_le_bytes() && bytes[8..24] == id.file
}

fn hash(bytes: &[u8; HEADER]) -> u64 {
    let mut copy = *bytes;
    copy[12] = 0;
    checksum(&copy[..248])
}

pub(super) fn open(
    parent: &relative::Directory,
    name: &OsStr,
    mut anchor: &File,
    principal: &Principal,
    clock: &mut Clock,
    config: Config,
) -> Result<(File, Journal<File>), Error> {
    let length = anchor.metadata()?.len();
    if length != 0 && length != HEADER as u64 {
        return Err(Error::Replaced);
    }
    let mut bytes = [0; HEADER];
    let root = principal.open_at(parent.handle(), name, length == 0, SHARED, true)?;
    let root_id = directory_identity(&root)?;
    let state = principal.open_at(&root, OsStr::new(STATE), length == 0, SHARED, false)?;
    let state_id = identity(&state)?;
    if root_id.volume != state_id.volume {
        return Err(Error::Replaced);
    }
    if length == 0 {
        if state.metadata()?.len() != 0 {
            return Err(Error::Replaced);
        }
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12] = PREPARING;
        getrandom::fill(&mut bytes[16..32]).map_err(io::Error::from)?;
        bytes[32..64].copy_from_slice(&clock.epoch.encode());
        bytes[64..132].copy_from_slice(&principal.sid_bytes);
        encode_id(&mut bytes[136..160], directory_identity(parent.handle())?);
        encode_id(&mut bytes[160..184], root_id);
        encode_id(&mut bytes[184..208], state_id);
        let checksum = hash(&bytes);
        bytes[248..].copy_from_slice(&checksum.to_le_bytes());
        anchor.seek(SeekFrom::Start(0))?;
        anchor.write_all(&bytes)?;
        anchor.flush()?;
    } else {
        anchor.seek(SeekFrom::Start(0))?;
        anchor.read_exact(&mut bytes)?;
    }
    if &bytes[..8] != MAGIC
        || bytes[8..12] != 1u32.to_le_bytes()
        || !matches!(bytes[12], PREPARING | READY)
        || bytes[13..16] != [0; 3]
        || bytes[132..136] != [0; 4]
        || bytes[208..248] != [0; 40]
        || hash(&bytes) != u64::from_le_bytes(bytes[248..].try_into().expect("checksum"))
        || bytes[16..32] == [0; 16]
        || bytes[64..132] != principal.sid_bytes
        || !matches_id(&bytes[136..160], directory_identity(parent.handle())?)
        || !matches_id(&bytes[160..184], root_id)
        || !matches_id(&bytes[184..208], state_id)
    {
        return Err(Error::Incompatible);
    }
    let retained = clock::Epoch::decode(bytes[32..64].try_into().expect("clock epoch"))?;
    clock.epoch.require_counter(retained).map_err(|_| Error::Incompatible)?;
    let generation = Generation(bytes[16..32].try_into().expect("generation"));
    let mut journal = if bytes[12] == PREPARING {
        let recovered = if state.metadata()?.len() > journal::HEADER {
            let mut journal = Journal::open(state.try_clone()?)?;
            match journal.load() {
                Ok(authority) => {
                    if authority.config() != config || authority.ledger().generation() != generation {
                        return Err(Error::Incompatible);
                    }
                    Some(journal)
                }
                Err(journal::Error::Uninitialized) => None,
                Err(error) => return Err(error.into()),
            }
        } else {
            None
        };
        match recovered {
            Some(journal) => journal,
            None => {
                // A short initial header cannot contain published accounting.
                // Reuse its pinned inode and the anchor's existing generation.
                state.set_len(0)?;
                let mut authority = Authority::new(generation, config, clock.now()?)?;
                authority.bind_clock(clock.binding());
                Journal::create(state, &authority)?
            }
        }
    } else {
        Journal::open(state)?
    };
    let authority = journal.load()?;
    if authority.config() != config || authority.ledger().generation() != generation {
        return Err(Error::Incompatible);
    }
    let binding = clock.retained_binding(authority.clock_binding(), retained, authority.now())?;
    if authority.clock_binding() != Some(binding) {
        // Publish the boot transition with the accounting it qualifies. A
        // partial write recovers the whole previous or next mapping, never a
        // new clock paired with old debt. Reopeners reuse this exact origin.
        journal.transaction(|state| {
            state.bind_clock(binding);
            Ok(())
        })?;
    }
    clock.bind(binding)?;
    if bytes[12] == PREPARING {
        anchor.seek(SeekFrom::Start(12))?;
        anchor.write_all(&[READY])?;
        anchor.flush()?;
    }
    Ok((root, journal))
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};

    use super::*;
    use crate::HostConfig;
    use crate::coordination::authority::{Config, Origin, Request};
    use crate::coordination::protocol::Work;
    use crate::coordination::windows::{Completion, Scope};

    fn prior_boot(epoch: clock::Epoch) -> clock::Epoch {
        let sequence = if epoch.sequence + 1 == u32::MAX { 1 } else { epoch.sequence + 1 };
        clock::Epoch { sequence, ..epoch }
    }

    fn change_creation_epoch(directory: &Path, epoch: clock::Epoch) {
        let mut anchor =
            OpenOptions::new().read(true).write(true).open(directory.join("coordination.authority.lock")).unwrap();
        let mut header = [0; HEADER];
        anchor.read_exact(&mut header).unwrap();
        header[32..64].copy_from_slice(&epoch.encode());
        let checksum = hash(&header);
        header[248..].copy_from_slice(&checksum.to_le_bytes());
        anchor.seek(SeekFrom::Start(0)).unwrap();
        anchor.write_all(&header).unwrap();
        anchor.flush().unwrap();
    }

    fn retained_journal(path: &Path) -> Journal<File> {
        Journal::open(OpenOptions::new().read(true).write(true).open(path.join(STATE)).unwrap()).unwrap()
    }

    #[test]
    fn retained_authority_reopens_after_a_boot_epoch_change_without_resetting_debt() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("coordination");
        let config = Config::from_host(&HostConfig::default(), 4, 8, 4).unwrap();
        let scope = Scope::open(&path, config).unwrap();
        let generation = scope.diagnostics().unwrap().generation;
        let epoch = scope.clock.epoch;
        let client = scope.join().unwrap();
        let mut prepared = client
            .prepare(Request {
                work: Work::LazyRead,
                origin: Origin::Foreground,
                domain: None,
                required: 1,
                desired: 0,
                ceiling_ns: u64::MAX,
            })
            .unwrap();
        prepared.try_run(|_| Completion { value: (), operations: 1, failed: false }).unwrap();
        let charged = scope.view().unwrap().charged_ns;
        drop((prepared, client, scope));

        let mut journal = retained_journal(&path);
        journal
            .transaction(|state| {
                let previous = ClockBinding::checked(prior_boot(epoch).encode(), 0).unwrap();
                state.bind_clock(previous);
                Ok(())
            })
            .unwrap();
        drop(journal);

        let reopened = Scope::open(&path, config).unwrap();
        assert_eq!(reopened.diagnostics().unwrap().generation, generation);
        assert!(reopened.view().unwrap().charged_ns >= charged);
    }

    #[test]
    fn reboot_mapping_is_shared_and_survives_every_handle_closing() {
        use std::time::Duration;

        use crate::coordination::protocol::{Progress, VERSION};

        // Cover migration from both counter-only and boot-mapped snapshots.
        for mapped in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("coordination");
            let config = Config::from_host(&HostConfig::default(), 4, 8, 4).unwrap();
            let scope = Scope::open(&path, config).unwrap();
            let generation = scope.generation;
            let epoch = scope.clock.epoch;
            drop(scope);
            let previous_epoch = prior_boot(epoch);
            change_creation_epoch(directory.path(), previous_epoch);

            // The prior logical timeline is deliberately below this boot's
            // raw QPC. An upward-only rebase would grant the elapsed uptime.
            let mut retained = Authority::new(generation, config, 12_000).unwrap();
            let participant = retained.join(VERSION).unwrap();
            let id = retained.ledger().next_operation(participant).unwrap();
            retained
                .prepare(
                    id,
                    Request {
                        work: Work::LazyRead,
                        origin: Origin::Foreground,
                        domain: None,
                        required: 1,
                        desired: 0,
                        ceiling_ns: u64::MAX,
                    },
                    12_000,
                )
                .unwrap();
            retained.authorize(id, 12_000).unwrap();
            retained.settle(id, Progress { revision: 1, operations: 1, elapsed_ns: 0, failed: false }, 12_000).unwrap();
            retained.leave(participant).unwrap();
            let charged = retained.view().charged_ns;
            assert!(charged > 0);
            if mapped {
                retained.bind_clock(ClockBinding::checked(previous_epoch.encode(), 0).unwrap());
            }
            let mut journal = retained_journal(&path);
            journal
                .transaction(|state| {
                    *state = retained.clone();
                    Ok(())
                })
                .unwrap();
            drop(journal);

            let first = Scope::open(&path, config).unwrap();
            let binding = first.clock.binding();
            assert_eq!(binding.epoch, epoch.encode());
            assert!(binding.offset_ns < 0);
            let mut journal = retained_journal(&path);
            let persisted = journal.load().unwrap();
            assert_eq!(persisted.clock_binding(), Some(binding));
            // Opening publishes a mapping, without advancing/refilling debt.
            assert_eq!(persisted.now(), 12_000);
            assert_eq!(persisted.view(), retained.view());
            drop(journal);

            let second = Scope::open(&path, config).unwrap();
            assert_eq!(second.clock.binding(), binding);
            let before = first.now().unwrap();
            drop((first, second));
            std::thread::sleep(Duration::from_millis(20));
            let reopened = Scope::open(&path, config).unwrap();
            assert_eq!(reopened.clock.binding(), binding);
            assert!(reopened.now().unwrap() >= before + 10_000_000);
            assert_eq!(reopened.generation, generation);
            assert_eq!(reopened.view().unwrap().charged_ns, charged);
        }
    }

    #[test]
    fn a_changed_persisted_mapping_fences_an_open_connection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("coordination");
        let config = Config::from_host(&HostConfig::default(), 4, 8, 4).unwrap();
        let scope = Scope::open(&path, config).unwrap();
        let mut changed = scope.clock.binding();
        changed.offset_ns += 1;
        let mut journal = retained_journal(&path);
        journal
            .transaction(|state| {
                state.bind_clock(changed);
                Ok(())
            })
            .unwrap();
        drop(journal);
        assert!(matches!(scope.view(), Err(Error::Incompatible)));
        assert!(scope.diagnostics().unwrap().failed);
    }
}
