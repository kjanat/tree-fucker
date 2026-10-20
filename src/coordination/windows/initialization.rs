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
    clock: &Clock,
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
    clock.epoch.require(retained).map_err(|_| Error::Incompatible)?;
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
                Journal::create(state, &Authority::new(generation, config, clock.now()?)?)?
            }
        }
    } else {
        Journal::open(state)?
    };
    let authority = journal.load()?;
    if authority.config() != config || authority.ledger().generation() != generation {
        return Err(Error::Incompatible);
    }
    if bytes[12] == PREPARING {
        anchor.seek(SeekFrom::Start(12))?;
        anchor.write_all(&[READY])?;
        anchor.flush()?;
    }
    Ok((root, journal))
}
