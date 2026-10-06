//! The archive of a compacted governance log mirror: the sealed segments
//! (events `1..=size`, as the mirror held them) copied to a directory the
//! operator keeps (a mounted volume, an object-store mount) before the
//! mirror drops them, and a manifest listing every one with its SHA-256.
//!
//! The state anchor's seal holds the SHA-256 of the manifest's canonical
//! form, the log's size and the chain head there ([`crate::anchor::Seal`]),
//! so the archive is checked against the anchor, not against itself: a
//! manifest that is not the anchored one, a segment whose bytes are not the
//! listed ones, a missing, reordered or replayed segment, a prefix that
//! does not end at the sealed head are each refused. Recovery reads
//! archived segments only when a restored database ends inside the sealed
//! prefix; the control plane's start never needs the archive (the
//! database's own log is checked at every start, and the mirror's tail
//! chains from the sealed head).
//!
//! Layout: `segments/<n>.jsonl` (the mirror's segment numbers and bytes,
//! unchanged) and `manifest-<size>.json`. Files are written create-only (an
//! existing file must hold identical bytes: archiving the same segment
//! again is harmless, a different one is refused), fsynced, and their
//! directory fsynced.
//!
//! Losing the archive costs availability, never safety: rollback and
//! truncation detection do not read it, and the database still holds every
//! event. It means a database restored from a backup older than the sealed
//! prefix cannot be brought back from the mirror alone (`export-governance-
//! log` from a newer database, or the archive's copy, restores it).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use encompute_ir::{Code, Error, Result};
use encompute_verification::service::sha256_hex;

use crate::anchor::{Seal, MIRROR_MAX_READ};
use crate::mirror::Segments;

/// The manifest's format version.
pub const MANIFEST_VERSION: u32 = 1;

fn archive_err(m: impl Into<String>) -> Error {
    Error::new(Code::TrustEvidence, m)
}

/// One archived segment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedSegment {
    pub n: u64,
    pub first: i64,
    pub last: i64,
    pub bytes: u64,
    pub sha256: String,
}

/// The retention policy a compaction ran with, recorded for the audit
/// trail. It is informational: it is **not** part of the manifest's digest
/// (so the seal does not commit to it), and neither verifying an archive nor
/// recovery reads it. Changing the retention of a later compaction never
/// changes how history sealed earlier verifies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionPolicy {
    /// A segment within this many events of the anchored size was kept.
    pub keep_events: i64,
    /// A segment whose last event was younger than this (seconds) was kept.
    pub min_age_secs: u64,
    /// When the compaction committed (seconds since the epoch).
    pub compacted_at: u64,
}

/// What the archive holds: the segments of events `1..=size`, in order,
/// and the chain head after the last.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub v: u32,
    pub size: i64,
    pub head: String,
    pub segments: Vec<ArchivedSegment>,
    /// How the compaction that wrote this manifest was configured. Absent
    /// from manifests written before it was recorded, which parse and
    /// digest exactly as before. Not covered by the digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<CompactionPolicy>,
}

/// The part of a manifest the seal commits to.
#[derive(Serialize)]
struct Committed<'a> {
    v: u32,
    size: i64,
    head: &'a str,
    segments: &'a [ArchivedSegment],
}

impl Manifest {
    /// SHA-256 of the canonical JSON of everything but the recorded policy:
    /// what the anchor's seal holds. It is the digest of the format before
    /// the policy was recorded, byte for byte.
    pub fn digest(&self) -> Result<String> {
        let c = Committed {
            v: self.v,
            size: self.size,
            head: &self.head,
            segments: &self.segments,
        };
        Ok(sha256_hex(
            &encompute_verification::canonical::canonical_json(&c)?,
        ))
    }

    /// The seal that commits to this manifest.
    pub fn seal(&self) -> Result<Seal> {
        Ok(Seal {
            size: self.size,
            head: self.head.clone(),
            manifest: self.digest()?,
        })
    }

    /// The segments cover events `1..=size` without gap or overlap.
    fn check_shape(&self) -> Result<()> {
        if self.v != MANIFEST_VERSION {
            return Err(archive_err(format!(
                "governance archive manifest version {}",
                self.v
            )));
        }
        let mut next = 1i64;
        let mut seen = std::collections::BTreeSet::new();
        for s in &self.segments {
            if s.first != next || s.last < s.first || !seen.insert(s.n) {
                return Err(archive_err(format!(
                    "governance archive manifest: segment {} (events {}..{}) does not follow event {}",
                    s.n,
                    s.first,
                    s.last,
                    next - 1
                )));
            }
            if s.bytes > MIRROR_MAX_READ {
                return Err(archive_err(format!(
                    "governance archive manifest: segment {} is larger than a segment may be",
                    s.n
                )));
            }
            next = s.last + 1;
        }
        if next - 1 != self.size {
            return Err(archive_err(format!(
                "governance archive manifest: its segments end at event {}, not at its size {}",
                next - 1,
                self.size
            )));
        }
        Ok(())
    }
}

/// A directory the archive is written to and read from.
pub struct Archive {
    dir: PathBuf,
}

fn file_err(p: &Path, e: impl std::fmt::Display) -> Error {
    archive_err(format!("governance archive {}: {e}", p.display()))
}

fn fsync_dir(d: &Path) -> Result<()> {
    std::fs::File::open(d)
        .and_then(|f| f.sync_all())
        .map_err(|e| file_err(d, e))
}

/// Writes `bytes` to `path` durably, create-only: written whole to a
/// temporary name (fsynced) and linked into place, so a crash leaves the
/// file whole or absent, never torn. An existing file must hold the same
/// bytes.
fn put(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().expect("a file in a directory");
    let same = |path: &Path| -> Result<()> {
        if read_bounded(path)? == bytes {
            Ok(())
        } else {
            Err(archive_err(format!(
                "governance archive {} exists with other content: refusing to replace it",
                path.display()
            )))
        }
    };
    if path.exists() {
        return same(path);
    }
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    let written = std::fs::File::create(&tmp).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(file_err(&tmp, e));
    }
    let linked = match std::fs::hard_link(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&tmp);
            return same(path);
        }
        // No hard links on this file system: rename (a single operator
        // writes an archive).
        Err(_) => std::fs::rename(&tmp, path),
    };
    let _ = std::fs::remove_file(&tmp);
    linked.map_err(|e| file_err(path, e))?;
    fsync_dir(dir)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(|e| file_err(path, e))?;
    let mut v = Vec::new();
    f.take(MIRROR_MAX_READ + 1)
        .read_to_end(&mut v)
        .map_err(|e| file_err(path, e))?;
    if v.len() as u64 > MIRROR_MAX_READ {
        return Err(file_err(path, "larger than a segment may be"));
    }
    Ok(v)
}

impl Archive {
    /// The archive in `dir`, created when `create`.
    pub fn open(dir: &Path, create: bool) -> Result<Self> {
        if create {
            std::fs::create_dir_all(dir.join("segments")).map_err(|e| file_err(dir, e))?;
        } else if !dir.is_dir() {
            return Err(archive_err(format!(
                "governance archive {}: no such directory",
                dir.display()
            )));
        }
        Ok(Self { dir: dir.into() })
    }

    fn segment_path(&self, n: u64) -> PathBuf {
        self.dir.join("segments").join(format!("{n:012}.jsonl"))
    }

    fn manifest_path(&self, size: i64) -> PathBuf {
        self.dir.join(format!("manifest-{size:012}.json"))
    }

    /// Archives segment `n` (its exact bytes): its manifest entry.
    pub fn put_segment(
        &self,
        n: u64,
        first: i64,
        last: i64,
        lines: &str,
    ) -> Result<ArchivedSegment> {
        put(&self.segment_path(n), lines.as_bytes())?;
        Ok(ArchivedSegment {
            n,
            first,
            last,
            bytes: lines.len() as u64,
            sha256: sha256_hex(lines.as_bytes()),
        })
    }

    /// Writes `m` (create-only; the same manifest again is harmless):
    /// its digest.
    pub fn put_manifest(&self, m: &Manifest) -> Result<String> {
        m.check_shape()?;
        let path = self.manifest_path(m.size);
        // A manifest of the same sealed content already there (an earlier
        // run that crashed before its commit) stays as it is, with the
        // policy it recorded: the policy is not part of what is sealed.
        if path.exists() {
            let old: Manifest = serde_json::from_slice(&read_bounded_manifest(&path)?)
                .map_err(|e| file_err(&path, e))?;
            if old.digest()? == m.digest()? {
                return m.digest();
            }
            return Err(archive_err(format!(
                "governance archive {} exists with other content: refusing to replace it",
                path.display()
            )));
        }
        let bytes = serde_json::to_vec_pretty(m).map_err(|e| archive_err(e.to_string()))?;
        put(&path, &bytes)?;
        m.digest()
    }

    /// The archive as the anchor's `seal` commits to it: the manifest is
    /// the sealed one (digest, size and head), well-formed, and every
    /// segment is read and checked against its listed bytes when
    /// `verify_files`, else on demand.
    pub fn load(&self, seal: &Seal, verify_files: bool) -> Result<Verified> {
        let p = self.manifest_path(seal.size);
        let m: Manifest =
            serde_json::from_slice(&read_bounded_manifest(&p)?).map_err(|e| file_err(&p, e))?;
        if m.digest()? != seal.manifest {
            return Err(archive_err(format!(
                "governance archive {}: not the manifest the state anchor sealed (its digest differs)",
                p.display()
            )));
        }
        if m.size != seal.size || m.head != seal.head {
            return Err(archive_err(format!(
                "governance archive {}: its size or head differs from the anchor's seal",
                p.display()
            )));
        }
        m.check_shape()?;
        let v = Verified {
            dir: self.dir.clone(),
            manifest: m,
        };
        if verify_files {
            for s in &v.manifest.segments {
                v.read(s.n)?;
            }
        }
        Ok(v)
    }
}

fn read_bounded_manifest(p: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    // A manifest lists a segment per few hundred events: far below this.
    const MAX: u64 = 64 * 1024 * 1024;
    let f = std::fs::File::open(p).map_err(|e| file_err(p, e))?;
    let mut v = Vec::new();
    f.take(MAX + 1)
        .read_to_end(&mut v)
        .map_err(|e| file_err(p, e))?;
    if v.len() as u64 > MAX {
        return Err(file_err(p, "larger than a manifest may be"));
    }
    Ok(v)
}

/// An archive whose manifest is the anchored one. Segments are served
/// only if their bytes are the listed ones.
pub struct Verified {
    dir: PathBuf,
    pub manifest: Manifest,
}

impl Verified {
    /// A listed segment's lines, after checking its length and SHA-256.
    pub fn read(&self, n: u64) -> Result<String> {
        let s = self
            .manifest
            .segments
            .iter()
            .find(|s| s.n == n)
            .ok_or_else(|| archive_err(format!("governance archive: segment {n} is not listed")))?;
        let p = self.dir.join("segments").join(format!("{n:012}.jsonl"));
        let bytes = read_bounded(&p)?;
        if bytes.len() as u64 != s.bytes || sha256_hex(&bytes) != s.sha256 {
            return Err(archive_err(format!(
                "governance archive {}: not the archived segment (its SHA-256 differs from the manifest's)",
                p.display()
            )));
        }
        String::from_utf8(bytes).map_err(|e| file_err(&p, e))
    }
}

impl Segments for Verified {
    fn list(&self) -> Result<Vec<u64>> {
        Ok(self.manifest.segments.iter().map(|s| s.n).collect())
    }

    fn read(&self, n: u64) -> Result<String> {
        Verified::read(self, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "encompute-archive-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// An archive of two segments (events 1..=3 and 4..=5).
    fn built(dir: &Path) -> (Archive, Manifest, Seal) {
        let a = Archive::open(dir, true).unwrap();
        let s1 = a.put_segment(1, 1, 3, "one\ntwo\nthree\n").unwrap();
        let s2 = a.put_segment(2, 4, 5, "four\nfive\n").unwrap();
        let m = Manifest {
            v: MANIFEST_VERSION,
            size: 5,
            head: "ab".repeat(32),
            segments: vec![s1, s2],
            policy: None,
        };
        a.put_manifest(&m).unwrap();
        let seal = m.seal().unwrap();
        (a, m, seal)
    }

    /// Files are written create-only: the same bytes again are harmless,
    /// other bytes under the same name are refused and nothing changes.
    #[test]
    fn files_are_written_once() {
        let dir = tmp("once");
        let (a, m, _) = built(&dir);
        a.put_segment(1, 1, 3, "one\ntwo\nthree\n").unwrap();
        a.put_manifest(&m).unwrap();
        // The same sealed content with another recorded policy keeps the
        // file; other sealed content is refused.
        let mut again = m.clone();
        again.policy = Some(CompactionPolicy {
            keep_events: 1,
            min_age_secs: 1,
            compacted_at: 1,
        });
        a.put_manifest(&again).unwrap();
        assert_eq!(
            Archive::open(&dir, false)
                .unwrap()
                .load(&m.seal().unwrap(), false)
                .unwrap()
                .manifest
                .policy,
            None
        );
        let mut other = m.clone();
        other.head = "cd".repeat(32);
        assert!(a.put_manifest(&other).is_err());
        let e = a.put_segment(1, 1, 3, "other\n").unwrap_err();
        assert!(e.message.contains("refusing to replace"), "{e}");
        assert_eq!(
            std::fs::read_to_string(dir.join("segments/000000000001.jsonl")).unwrap(),
            "one\ntwo\nthree\n"
        );
        // No temporary file is left behind.
        for d in [dir.clone(), dir.join("segments")] {
            for e in std::fs::read_dir(d).unwrap() {
                let n = e.unwrap().file_name().to_string_lossy().into_owned();
                assert!(!n.ends_with(".tmp"), "{n}");
            }
        }
    }

    /// The manifest is checked against the seal, and every segment against
    /// the manifest's bytes.
    #[test]
    fn the_seal_commits_to_the_manifest_and_the_manifest_to_the_bytes() {
        let dir = tmp("load");
        let (a, m, seal) = built(&dir);
        let v = a.load(&seal, true).unwrap();
        assert_eq!(v.read(2).unwrap(), "four\nfive\n");
        assert!(v.read(3).is_err(), "an unlisted segment");
        // A seal for another manifest, size or head.
        for bad in [
            Seal {
                manifest: "00".repeat(32),
                ..seal.clone()
            },
            Seal {
                head: "00".repeat(32),
                ..seal.clone()
            },
        ] {
            assert!(a.load(&bad, false).is_err());
        }
        // A changed segment: refused when it is read (and by verify).
        std::fs::write(dir.join("segments/000000000002.jsonl"), "FOUR\nfive\n").unwrap();
        assert!(a
            .load(&seal, false)
            .unwrap()
            .read(2)
            .unwrap_err()
            .message
            .contains("SHA-256"));
        assert!(a.load(&seal, true).is_err());
        // A manifest rewritten to match is not the sealed one.
        let mut m2 = m.clone();
        m2.segments[1].sha256 = sha256_hex(b"FOUR\nfive\n");
        std::fs::write(
            dir.join(format!("manifest-{:012}.json", m.size)),
            serde_json::to_vec_pretty(&m2).unwrap(),
        )
        .unwrap();
        let e = a.load(&seal, false).err().unwrap();
        assert!(
            e.message
                .contains("not the manifest the state anchor sealed"),
            "{e}"
        );
    }

    /// A manifest must cover events 1..=size without gap, overlap or
    /// repeated numbers.
    #[test]
    fn a_manifest_must_be_contiguous() {
        let dir = tmp("shape");
        let (a, m, _) = built(&dir);
        let mut gap = m.clone();
        gap.segments[1].first = 5;
        assert!(a.put_manifest(&gap).is_err());
        let mut short = m.clone();
        short.segments.pop();
        assert!(a.put_manifest(&short).is_err());
        let mut twice = m.clone();
        twice.segments[1].n = 1;
        assert!(a.put_manifest(&twice).is_err());
        let mut v = m;
        v.v = 9;
        assert!(a.put_manifest(&v).is_err());
    }

    /// The recorded retention policy is informational: a manifest with any
    /// policy, or none (the format before it was recorded), has the same
    /// digest, so one seal verifies all of them, and the policy is read back
    /// as written.
    #[test]
    fn the_recorded_policy_is_not_part_of_what_the_seal_commits_to() {
        let dir = tmp("policy");
        let (a, m, seal) = built(&dir);
        // The digest of the format without the field, spelled out.
        let legacy = sha256_hex(
            &encompute_verification::canonical::canonical_json(&serde_json::json!({
                "v": m.v, "size": m.size, "head": m.head, "segments": m.segments,
            }))
            .unwrap(),
        );
        assert_eq!(m.digest().unwrap(), legacy);
        assert_eq!(seal.manifest, legacy);
        for (keep, age, at) in [(10_000, 30 * 86_400, 1u64), (0, 0, 2), (7, 9, u64::MAX / 2)] {
            let mut with = m.clone();
            with.policy = Some(CompactionPolicy {
                keep_events: keep,
                min_age_secs: age,
                compacted_at: at,
            });
            assert_eq!(with.digest().unwrap(), legacy);
            assert_eq!(with.seal().unwrap(), seal);
            // Rewrite the manifest file with this policy: the sealed
            // archive still loads and every segment still verifies.
            std::fs::write(
                dir.join(format!("manifest-{:012}.json", m.size)),
                serde_json::to_vec_pretty(&with).unwrap(),
            )
            .unwrap();
            let v = a.load(&seal, true).unwrap();
            assert_eq!(v.manifest.policy, with.policy);
            assert_eq!(v.read(1).unwrap(), "one\ntwo\nthree\n");
        }
        // A manifest as the earlier format wrote it (no policy key).
        std::fs::write(
            dir.join(format!("manifest-{:012}.json", m.size)),
            serde_json::to_vec_pretty(&serde_json::json!({
                "v": m.v, "size": m.size, "head": m.head, "segments": m.segments,
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(a.load(&seal, true).unwrap().manifest.policy, None);
        // What the seal does commit to is still checked: a changed segment
        // list is refused whatever policy it carries.
        let mut tampered = m.clone();
        tampered.segments[0].sha256 = "00".repeat(32);
        tampered.policy = m.policy.clone();
        std::fs::write(
            dir.join(format!("manifest-{:012}.json", m.size)),
            serde_json::to_vec_pretty(&tampered).unwrap(),
        )
        .unwrap();
        assert!(a.load(&seal, false).is_err());
    }
}
