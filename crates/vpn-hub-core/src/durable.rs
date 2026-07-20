use std::{fs, io, io::Write as _, path::Path};

/// Injectable file-system boundary for durable settings commits.
pub trait DurableFileOps {
    /// Creates the complete directory path.
    ///
    /// # Errors
    ///
    /// Returns the underlying file-system error.
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
    /// Writes the complete byte slice to a file.
    ///
    /// # Errors
    ///
    /// Returns the underlying file-system error.
    fn write(&self, path: &Path, content: &[u8]) -> io::Result<()>;
    /// Flushes file content and metadata to durable storage.
    ///
    /// # Errors
    ///
    /// Returns the underlying file-system error.
    fn sync_file(&self, path: &Path) -> io::Result<()>;
    /// Renames a file-system entry.
    ///
    /// # Errors
    ///
    /// Returns the underlying file-system error.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    /// Removes a file-system entry.
    ///
    /// # Errors
    ///
    /// Returns the underlying file-system error.
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    /// Flushes directory metadata to durable storage.
    ///
    /// # Errors
    ///
    /// Returns the underlying file-system error.
    fn sync_directory(&self, path: &Path) -> io::Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDurableFileOps;

impl DurableFileOps for SystemDurableFileOps {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)
    }

    fn write(&self, path: &Path, content: &[u8]) -> io::Result<()> {
        let mut file = fs::File::create(path)?;
        file.write_all(content)
    }

    fn sync_file(&self, path: &Path) -> io::Result<()> {
        fs::OpenOptions::new().write(true).open(path)?.sync_all()
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        sync_directory(path)
    }
}

/// Durably replaces a file and leaves a byte-identical adjacent `.bak` copy.
/// A successful return means both contents and every namespace mutation have
/// crossed an explicit persistence barrier.
///
/// # Errors
///
/// Returns the first file-system or persistence-barrier error.
pub fn durable_atomic_save_with_backup<O: DurableFileOps + ?Sized>(
    path: &Path,
    content: &[u8],
    operations: &O,
) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    operations.create_dir_all(parent)?;
    operations.sync_directory(parent)?;

    let temporary = temporary_path(path, "new");
    let backup = backup_path(path);
    let backup_temporary = temporary_path(&backup, "new");
    remove_if_exists(&temporary, parent, operations)?;
    remove_if_exists(&backup_temporary, parent, operations)?;
    operations.write(&temporary, content)?;
    operations.sync_file(&temporary)?;

    if path.exists() {
        remove_if_exists(&backup, parent, operations)?;
        operations.rename(path, &backup)?;
        operations.sync_directory(parent)?;
    }
    if let Err(error) = operations.rename(&temporary, path) {
        if backup.exists() && !path.exists() {
            let _ = operations.rename(&backup, path);
            let _ = operations.sync_directory(parent);
        }
        return Err(error);
    }
    operations.sync_directory(parent)?;

    operations.write(&backup_temporary, content)?;
    operations.sync_file(&backup_temporary)?;
    remove_if_exists(&backup, parent, operations)?;
    operations.rename(&backup_temporary, &backup)?;
    operations.sync_directory(parent)
}

/// Writes a new file and persists its parent directory entry.
///
/// # Errors
///
/// Returns the first file-system or persistence-barrier error.
pub fn durable_write_new<O: DurableFileOps + ?Sized>(
    path: &Path,
    content: &[u8],
    operations: &O,
) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    operations.create_dir_all(parent)?;
    operations.sync_directory(parent)?;
    operations.write(path, content)?;
    operations.sync_file(path)?;
    operations.sync_directory(parent)
}

/// Durably replaces one file without creating another backup. A surrounding
/// journal must remain present until this operation and its directory flush
/// complete so an interrupted restore can be retried.
///
/// # Errors
///
/// Returns the first file-system or persistence-barrier error.
pub fn durable_replace<O: DurableFileOps + ?Sized>(
    path: &Path,
    content: &[u8],
    operations: &O,
) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    operations.create_dir_all(parent)?;
    operations.sync_directory(parent)?;
    let temporary = temporary_path(path, "restore");
    remove_if_exists(&temporary, parent, operations)?;
    operations.write(&temporary, content)?;
    operations.sync_file(&temporary)?;
    remove_if_exists(path, parent, operations)?;
    operations.rename(&temporary, path)?;
    operations.sync_directory(parent)
}

/// Removes a file and persists the directory entry change.
///
/// # Errors
///
/// Returns the first file-system or persistence-barrier error.
pub fn durable_remove_if_exists<O: DurableFileOps + ?Sized>(
    path: &Path,
    operations: &O,
) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    remove_if_exists(path, parent, operations)
}

fn remove_if_exists<O: DurableFileOps + ?Sized>(
    path: &Path,
    parent: &Path,
    operations: &O,
) -> io::Result<()> {
    match operations.remove_file(path) {
        Ok(()) => operations.sync_directory(parent),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn backup_path(path: &Path) -> std::path::PathBuf {
    let mut extension = path
        .extension()
        .map_or_else(String::new, |value| value.to_string_lossy().into_owned());
    if !extension.is_empty() {
        extension.push('.');
    }
    extension.push_str("bak");
    path.with_extension(extension)
}

fn temporary_path(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut extension = path
        .extension()
        .map_or_else(String::new, |value| value.to_string_lossy().into_owned());
    if !extension.is_empty() {
        extension.push('.');
    }
    extension.push_str(suffix);
    path.with_extension(extension)
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;

    fs::OpenOptions::new()
        .access_mode(GENERIC_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_WRITE_THROUGH)
        .open(path)?
        .sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, collections::BTreeSet};

    struct FailingOps {
        inner: SystemDurableFileOps,
        fail_at: usize,
        operation: Cell<usize>,
    }

    impl FailingOps {
        fn gate(&self) -> io::Result<()> {
            let next = self.operation.get() + 1;
            self.operation.set(next);
            if next == self.fail_at {
                Err(io::Error::other("injected durable boundary failure"))
            } else {
                Ok(())
            }
        }
    }

    impl DurableFileOps for FailingOps {
        fn create_dir_all(&self, path: &Path) -> io::Result<()> {
            self.gate()?;
            self.inner.create_dir_all(path)
        }
        fn write(&self, path: &Path, content: &[u8]) -> io::Result<()> {
            self.gate()?;
            self.inner.write(path, content)
        }
        fn sync_file(&self, path: &Path) -> io::Result<()> {
            self.gate()?;
            self.inner.sync_file(path)
        }
        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            self.gate()?;
            self.inner.rename(from, to)
        }
        fn remove_file(&self, path: &Path) -> io::Result<()> {
            self.gate()?;
            self.inner.remove_file(path)
        }
        fn sync_directory(&self, path: &Path) -> io::Result<()> {
            self.gate()?;
            self.inner.sync_directory(path)
        }
    }

    #[test]
    fn every_atomic_save_boundary_leaves_only_old_or_new_documents() {
        let mut observed_failures = BTreeSet::new();
        for fail_at in 1..=32 {
            let directory = tempfile::tempdir().expect("tempdir");
            let path = directory.path().join("settings.toml");
            durable_atomic_save_with_backup(&path, b"old", &SystemDurableFileOps)
                .expect("old fixture");
            let operations = FailingOps {
                inner: SystemDurableFileOps,
                fail_at,
                operation: Cell::new(0),
            };
            let result = durable_atomic_save_with_backup(&path, b"new", &operations);
            if result.is_ok() {
                break;
            }
            observed_failures.insert(fail_at);
            for candidate in [&path, &backup_path(&path)] {
                if let Ok(content) = fs::read(candidate) {
                    assert!(content == b"old" || content == b"new");
                }
            }
            assert!(path.exists() || backup_path(&path).exists());
        }
        assert!(observed_failures.len() >= 12);
    }

    #[test]
    fn owned_directory_metadata_can_be_flushed() {
        let directory = tempfile::tempdir().expect("tempdir");
        SystemDurableFileOps
            .sync_directory(directory.path())
            .expect("directory metadata flush");
    }
}
