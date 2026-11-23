//! Reading files that hold secret keys, under one permission policy.
//!
//! Two kinds, matching the checks Encompute already makes elsewhere:
//!
//! - [`SecretFile::Private`]: a key a user keeps for themselves (a client's
//!   `secret.key`, a party identity key). Owner only: no access for the
//!   group or others (`chmod 600`), as for the evaluator identity and the
//!   key broker's KEK.
//! - [`SecretFile::Mounted`]: a key a service reads from a mounted secret
//!   (`ENCOMPUTE_SERVICE_KEY_FILE`, `ENCOMPUTE_SIGNING_KEY_FILE`). A
//!   container bind mount keeps the host's mode while the service runs as
//!   another user, so the file may be readable by others (0644, inside a
//!   0700 directory, as `deploy/docker-compose/init.sh` makes it), but never
//!   writable by the group or others, who could substitute the key. This is
//!   the rule the OpenBao token file already follows.
//!
//! Both refuse anything but a regular file. The mode is read from the
//! opened file, not looked up by path first, so the file checked is the
//! file read. Platforms without Unix modes are not checked.

use std::io::Read;
use std::path::Path;

use encompute_ir::{Code, Error, Result};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretFile {
    /// Owner only (0600).
    Private,
    /// Not writable by the group or others (0644 allowed).
    Mounted,
}

impl SecretFile {
    /// Mode bits that must be clear.
    fn forbidden(self) -> u32 {
        match self {
            SecretFile::Private => 0o077,
            SecretFile::Mounted => 0o022,
        }
    }

    fn advice(self) -> &'static str {
        match self {
            SecretFile::Private => {
                "a secret key file must be accessible to its owner only (chmod 600)"
            }
            SecretFile::Mounted => {
                "a mounted secret must be a regular file writable by its owner only (chmod 600, \
                 or 644 for a mounted secret)"
            }
        }
    }
}

/// Read a secret file of `kind`. An I/O error (missing file, no access) is
/// mapped by `io_err`, so callers keep their own error codes for it; a file
/// with unsafe permissions is refused with ENC2605 (insecure
/// configuration).
pub fn read_secret_file(
    path: &Path,
    kind: SecretFile,
    io_err: impl Fn(std::io::Error) -> Error,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut f = std::fs::File::open(path).map_err(&io_err)?;
    check(&f, path, kind, &io_err)?;
    let mut bytes = Zeroizing::new(Vec::new());
    f.read_to_end(&mut bytes).map_err(&io_err)?;
    Ok(bytes)
}

#[cfg(unix)]
fn check(
    f: &std::fs::File,
    path: &Path,
    kind: SecretFile,
    io_err: &impl Fn(std::io::Error) -> Error,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let m = f.metadata().map_err(io_err)?;
    let mode = m.permissions().mode() & 0o777;
    if !m.is_file() || mode & kind.forbidden() != 0 {
        return Err(Error::new(
            Code::InsecureConfiguration,
            format!(
                "{} is {}: {}",
                path.display(),
                if m.is_file() {
                    format!("mode {mode:o}")
                } else {
                    "not a regular file".to_owned()
                },
                kind.advice()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check(
    _f: &std::fs::File,
    _path: &Path,
    _kind: SecretFile,
    _io_err: &impl Fn(std::io::Error) -> Error,
) -> Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "encompute-secret-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn io(e: std::io::Error) -> Error {
        Error::new(Code::WrongKey, e.to_string())
    }

    fn with_mode(d: &Path, mode: u32) -> std::path::PathBuf {
        let p = d.join(format!("key-{mode:o}"));
        std::fs::write(&p, [7u8; 32]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[test]
    fn private_files_are_owner_only() {
        let d = dir();
        for mode in [0o600, 0o400] {
            let p = with_mode(&d, mode);
            assert_eq!(
                read_secret_file(&p, SecretFile::Private, io)
                    .unwrap()
                    .as_slice(),
                &[7u8; 32]
            );
        }
        for mode in [0o640, 0o604, 0o644, 0o660, 0o666, 0o610] {
            let p = with_mode(&d, mode);
            let e = read_secret_file(&p, SecretFile::Private, io).unwrap_err();
            assert_eq!(e.code, Code::InsecureConfiguration, "{mode:o}");
            assert!(e.message.contains("chmod 600"), "{}", e.message);
        }
    }

    #[test]
    fn mounted_secrets_may_be_readable_but_never_writable_by_others() {
        let d = dir();
        for mode in [0o600, 0o644, 0o444, 0o640] {
            let p = with_mode(&d, mode);
            assert!(
                read_secret_file(&p, SecretFile::Mounted, io).is_ok(),
                "{mode:o}"
            );
        }
        for mode in [0o620, 0o602, 0o666, 0o664, 0o646] {
            let p = with_mode(&d, mode);
            let e = read_secret_file(&p, SecretFile::Mounted, io).unwrap_err();
            assert_eq!(e.code, Code::InsecureConfiguration, "{mode:o}");
        }
    }

    #[test]
    fn only_regular_files_and_io_errors_keep_the_callers_code() {
        let d = dir();
        let e = read_secret_file(&d, SecretFile::Mounted, io).unwrap_err();
        assert!(
            e.code == Code::InsecureConfiguration || e.code == Code::WrongKey,
            "{e:?}"
        );
        let e = read_secret_file(&d.join("missing"), SecretFile::Private, io).unwrap_err();
        assert_eq!(e.code, Code::WrongKey);
    }
}
