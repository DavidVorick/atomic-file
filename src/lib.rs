#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused_must_use)]
#![deny(unused_mut)]

//! The AtomicFile crate provides a wrapper to async_std::File to enable more convenient and safe
//! interactions with on-disk data. All operations on AtomicFile are ACID, and the AtomicFile type
//! includes an invisible 4096 byte header which manages details like version number and file
//! identifier.
//!
//! The main use of a version number and file identifier are to provide easy upgrade capabilities
//! for AtomicFiles, and also to ensure that the wrong file is never being opened.
//!
//! The main advantage of using an AtomicFile is its ACID compliance, which ensures that data will
//! never be corrupted in the event of a sudden loss of power. Typical file usage patters leave
//! users vulnerable to corruption, especially when updating a file. AtomicFile protects against
//! corruption by using a double-write scheme to guarantee that correct data exists on disk, and
//! uses a checksum to verify at startup that the correct instance of the doubly-written file is
//! loaded. This does mean that two files will exist on disk for each AtomicFile - a .atomic_file
//! and a .atomic_file_backup.
//!
//! Data corruption can still occur in the event of something extreme like physical damage to the
//! hard drive, but changes of recovery are better and the user is protected against all common
//! forms of corruption (which stem from power being lost unexpectedly).
//!
//! The 'Atomic' property of the AtomicFile is that the only read and write operations fully read
//! or fully write the file.
//! ```
//! // Basic file operations
//!
//! use std::path::PathBuf;
//! use atomic_file::open_file_v1;
//!
//! #[async_std::main]
//! async fn main() {
//!     // Create a version 1 file with open_file_v1. If no file exists yet, a new blank file
//!     // will be created.
//!     let mut path = PathBuf::new();
//!     path.push("target");
//!     path.push("docs-example-1");
//!     let identifier = "AtomicFileDocs::docs-example-1";
//!     let mut file = open_file_v1(&path, identifier).await.unwrap();
//!     // The above call is an alias of 'open_file(&path, identifier, 1, Vec::new())'
//!
//!     // Use 'contents' and 'write_file' to read and write the logical data of the file. Each
//!     // one will always read or write the full contents of the file.
//!     file.write_file(b"hello, world!").await.unwrap();
//!     let file_data = file.contents();
//!     if file_data != b"hello, world!" {
//!         panic!("example did not read correctly");
//!     }
//!     # drop(file);
//!     # atomic_file::delete_file(&path).await.unwrap();
//! }
//! ```
//! AtomicFile uses a versioning and upgrading scheme to simplify the process of releasing new
//! versions of a file. When opening a file, you pass in a version number and an upgrade path which
//! will allow the file opening process to automatically upgrade your files from their current
//! version to the latest version.
//! ```
//! // Simple upgrade example
//! use std::path::PathBuf;
//!
//! use anyhow::{bail, Result, Error};
//! use atomic_file::{open_file, wrap_upgrade_process, AtomicFile, Upgrade};
//!
//! // An example of a function that upgrades a file from version 1 to version 2, while making
//! // changes to the body of the file.
//! async fn example_upgrade(
//!     data: Vec<u8>,
//!     initial_version: u8,
//!     updated_version: u8,
//! ) -> Result<Vec<u8>, Error> {
//!     // Check that the version is okay.
//!     if initial_version != 1 || updated_version != 2 {
//!         bail!("wrong version");
//!     }
//!
//!     // Return updated contents for the file.
//!     Ok((b"hello, update!".to_vec()))
//! }
//!
//! #[async_std::main]
//! async fn main() {
//!     # let mut p = PathBuf::new();
//!     # p.push("target");
//!     # p.push("docs-example-2");
//!     # let i = "AtomicFileDocs::docs-example-2";
//!     # let mut f = atomic_file::open_file_v1(&p, i).await.unwrap();
//!     # f.write_file(b"hello, world!").await.unwrap();
//!     # drop(f);
//!     let mut path = PathBuf::new();
//!     path.push("target");
//!     path.push("docs-example-2");
//!     let identifier = "AtomicFileDocs::docs-example-2";
//!     let upgrade = Upgrade {
//!         initial_version: 1,
//!         updated_version: 2,
//!         process: wrap_upgrade_process(example_upgrade),
//!     };
//!     let mut file = open_file(&path, identifier, 2, &vec![upgrade]).await.unwrap();
//!     // Note that the wrap_upgrade_process call is necessary to create the correct function
//!     // pointer for the upgrade. Also note that the upgrades are passed in as a vector,
//!     // allowing the caller to define upgrades for 1 -> 2, 2 -> 3, etc, which will all be
//!     // called in a chain, such that the call to 'open' does not return until the file
//!     // has been upgraded all the way to the latest version.
//!     let file_data = file.contents();
//!     if file_data != b"hello, update!" {
//!         panic!("upgrade appears to have failed: \n{:?}\n{:?}", file_data, b"hello, update!");
//!     }
//!
//!     // Perform cleanup.
//!     drop(file);
//!     atomic_file::delete_file(&path).await.unwrap();
//! }
//! ```
//!
//! If you would like to contribute to this crate, the implementation of the 'Upgrade' is
//! particularly gnarly, owing to me being unable to figure out the best way to approach function
//! pointers in Rust. If you know of a cleaner or simpler implementation, a pull request is warmly
//! welcomed.

use async_std::fs::{File, OpenOptions};
use async_std::io::prelude::SeekExt;
use async_std::io::{ReadExt, SeekFrom, WriteExt};
use async_std::prelude::Future;
use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::from_utf8;

use anyhow::{bail, Context, Error, Result};
use sha2::{Digest, Sha256};

/// UpgradeFunc defines the signature for a function that can be used to upgrade an
/// AtomicFile. The UpgradeFunc function will receive the file data that needs to be upgraded along
/// with the intended initial version and final version that is expected from the upgrade.
///
/// We pass in the initial version and final version as arguments to provide an extra level of
/// redundancy and to prevent mistakes when copy-pasting upgrades, as an incorrect upgrade could
/// corrupt user data.
pub type UpgradeFunc =
    fn(data: Vec<u8>, initial_version: u8, upgraded_version: u8) -> Result<Vec<u8>, Error>;

/// WrappedUpgradeFunc is a type that wraps an UpgradeFunc so that the UpgradeFunc can be
/// used as a function pointer in the call to `open_file`.
pub type WrappedUpgradeFunc =
    Box<dyn Fn(Vec<u8>, u8, u8) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>>>>>;

/// wrap_upgrade_process is a function that will convert an UpgradeFunc into a
/// WrappedUpgradeFunc.
pub fn wrap_upgrade_process<T>(f: fn(Vec<u8>, u8, u8) -> T) -> WrappedUpgradeFunc
where
    T: Future<Output = Result<Vec<u8>, Error>> + 'static,
{
    Box::new(move |x, y, z| Box::pin(f(x, y, z)))
}

/// Upgrade defines an upgrade process for upgrading the data in a file from one version to
/// another.
pub struct Upgrade {
    /// initial_version designates the version of the file that this upgrade should be applied to.
    pub initial_version: u8,
    /// updated_version designates the version of the file after the upgrade is complete.
    pub updated_version: u8,
    /// process defines the function that is used to upgrade the file.
    pub process: WrappedUpgradeFunc,
}

/// AtompicFile defines the main type for the crate, and implements an API for safely
/// handling atomic files. The API is based on the async_std::File interface, but with some
/// adjustments that are designed to make it both safer and more ergonomic. For example, len() is a
/// direct call rather than a property of a metadata() call.
#[derive(Debug)]
pub struct AtomicFile {
    backup_file: File,
    file: File,
    identifier: String,
    logical_data: Vec<u8>,
    version: u8,
}

/// add_extension will add a new extension to the provided pathbuf, rather than overwriting the
/// existing one. For example, 'add_extension("stuff.tar", "gz")' returns 'stuff.tar.gz', while
/// calling set_extension directly would return 'stuff.gz', which is the wrong result.
fn add_extension(path: &mut PathBuf, extension: &str) {
    match path.extension() {
        Some(ext) => {
            let mut ext = ext.to_os_string();
            ext.push(".");
            ext.push(extension);
            path.set_extension(ext)
        }
        None => path.set_extension(extension),
    };
}

/// version_to_bytes will write out the version in ascii, adding leading zeroes if needed and
/// placing a newline at the end.
fn version_to_bytes(version: u8) -> [u8; 4] {
    // 0 is not an allowed version, every other possible u8 is okay.
    if version == 0 {
        panic!("version is not allowed to be 0");
    }

    // Compute the 4 version bytes based on the latest version.
    let mut version_string = format!("{}\n", version);
    if version_string.len() == 2 {
        version_string = format!("00{}", version_string);
    } else if version_string.len() == 3 {
        version_string = format!("0{}", version_string);
    }
    let version_bytes = version_string.as_bytes();
    let mut version_arr = [0u8; 4];
    version_arr.copy_from_slice(version_bytes);
    version_arr
}

/// identifier_and_version_from_metadata will pull the identifier and version out of the metadata.
fn identifier_and_version_from_metadata(metadata: &[u8]) -> Result<(String, u8), Error> {
    if metadata.len() < 4096 {
        bail!("provided metadata is not the right size");
    }

    let version_str =
        from_utf8(&metadata[33..36]).context("the on-disk version could not be parsed")?;
    let version: u8 = version_str
        .parse()
        .context("unable to parse version of metadata")?;

    let mut clean_identifier = false;
    let mut identifier = "".to_string();
    for i in 0..201 {
        if metadata[i + 37] == '\n' as u8 && metadata[i + 37 + 1] == 255 {
            clean_identifier = true;
            break;
        }
        if metadata[i + 37] > 127 {
            bail!("identifier contains non-ascii characters before termination sequence");
        }
        identifier.push(metadata[i + 37] as char);
    }
    if !clean_identifier {
        bail!("provided metadata does not have a legally terminating identifier");
    }

    Ok((identifier, version))
}

impl AtomicFile {
    /// fill_metadata will write the first 4096 bytes to contain the proper metadata for the file,
    /// including the first 32 bytes which serve as the checksum.
    fn fill_metadata(&self, buf: &mut [u8]) {
        if buf.len() < 4096 {
            panic!("misuse of fill_metadata, check stack trace");
        }
        if self.identifier.len() > 200 {
            panic!(
                "file has too-large identifier, ensure bounds checking is in place in open_file"
            );
        }
        let version_bytes = version_to_bytes(self.version);

        // Fill out the header data.
        buf[32] = '\n' as u8;
        buf[33..37].copy_from_slice(&version_bytes);
        let iden_bytes = self.identifier.as_bytes();
        buf[37..37 + iden_bytes.len()].copy_from_slice(iden_bytes);
        buf[37 + iden_bytes.len()] = '\n' as u8;
        buf[38 + iden_bytes.len()] = 255; // newline+255 is the termination sequence for identifier
        buf[4095] = '\n' as u8;

        // Grab the checksum of the data and fill it in as the first 32 bytes.
        let mut hasher = Sha256::new();
        hasher.update(&buf[32..]);
        let result = hasher.finalize();
        buf[..32].copy_from_slice(&result);
    }

    /// len will return the size of the file, not including the versioned header.
    pub fn len(&self) -> usize {
        self.logical_data.len()
    }

    /// contents will return a copy of the contents of the file.
    pub fn contents(&self) -> Vec<u8> {
        self.logical_data.clone()
    }

    /// write_file will perform a safe, ACID operation to write the provided data to the file. This
    /// will incur a performance cost of 2 fsyncs and of writing the full contents of the file to
    /// disk twice. For SSDs, the cost of two fsyncs is typically under 25ms and often under 3ms.
    /// For HDDs, the cost of two fsyncs is typically over 200ms and often over 800ms.
    pub async fn write_file(&mut self, buf: &[u8]) -> Result<(), Error> {
        // Build the full physical data of the file, including the leading checksum in the
        // metadata.
        let mut full_data = vec![0u8; 4096 + buf.len()];
        full_data[4096..].copy_from_slice(buf);
        self.fill_metadata(&mut full_data);

        // Write out the full data to the backup file.
        self.backup_file
            .set_len(full_data.len() as u64)
            .await
            .context("unable to set the length of the backup file")?;
        self.backup_file
            .seek(SeekFrom::Start(0))
            .await
            .context("unable to seek to start of backup file")?;
        self.backup_file
            .write_all(&full_data)
            .await
            .context("unable to write to backup file")?;
        self.backup_file
            .flush()
            .await
            .context("unable to flush backup file")?;
        self.backup_file
            .sync_all()
            .await
            .context("fsync of backup file failed")?;

        // Backup file is safe, repeat the operation on the main file.
        self.file
            .set_len(full_data.len() as u64)
            .await
            .context("unable to set the length of the backup file")?;
        self.file
            .seek(SeekFrom::Start(0))
            .await
            .context("unable to seek to start of backup file")?;
        self.file
            .write_all(&full_data)
            .await
            .context("unable to write to backup file")?;
        self.file
            .flush()
            .await
            .context("unable to flush backup file")?;
        self.file
            .sync_all()
            .await
            .context("fsync of backup file failed")?;

        // Set the data of the file to the newly provided data.
        self.logical_data = buf.to_vec();
        Ok(())
    }
}

/// verify_upgrade_paths verify that the set of paths provided for performing upgrades all lead to
/// the latest version, and will return an error if some path doesn't lead to the latest version.
/// It will also return an error if two possible paths exist for a given version.
fn verify_upgrade_paths(
    upgrade_paths: &Vec<Upgrade>,
    current_version: u8,
    latest_version: u8,
) -> Result<(), Error> {
    // Enusre 0 was not used as the latest_version.
    if latest_version == 0 {
        bail!("version 0 is not allowed for a VersionedFile");
    }

    // Verify that an upgrade path exists for the file which carries it to the latest version.
    let mut version_routes = HashMap::new();
    // Verify basic properties of the graph (no cycles, no repeat sources).
    for path in upgrade_paths {
        if path.initial_version >= path.updated_version {
            bail!("upgrade paths must always lead to a higher version number");
        }
        if version_routes.contains_key(&path.initial_version) {
            bail!("upgrade paths can only have one upgrade for each version");
        }
        if path.updated_version > latest_version {
            bail!("upgrade paths lead beyond the latest version");
        }
        if path.initial_version == 0 {
            bail!("version 0 is not allowed for a VersionedFile");
        }
        version_routes.insert(path.initial_version, path.updated_version);
    }
    // Verify that all upgrades lead to the latest version. We iterate over the version_routes and mark every
    // node that connects to a finished node.
    let mut complete_paths = HashMap::new();
    complete_paths.insert(latest_version, {});
    loop {
        let mut progress = false;
        let mut finished = true;

        for (key, value) in &version_routes {
            if complete_paths.contains_key(key) {
                continue;
            }
            if complete_paths.contains_key(value) {
                progress = true;
                complete_paths.insert(*key, {});
            } else {
                finished = false;
            }
        }

        if finished {
            break;
        }
        if progress == false {
            bail!("update graph is incomplete, not all nodes lead to the latest version");
        }
    }
    // Verify that the current version of the file is found in the upgrade paths.
    if !complete_paths.contains_key(&current_version) {
        bail!("no upgrade found for current version of file");
    }
    Ok(())
}

/// perform_file_upgrade takes a file and an upgrade, and then executes the upgrade against the
/// file.
async fn perform_file_upgrade(file: &mut AtomicFile, u: &Upgrade) -> Result<(), Error> {
    // Check that we've got the right upgrade.
    if file.version != u.initial_version {
        bail!("wrong update has been selected for this file");
    }

    // Perform the update on the data.
    let new_data = (u.process)(file.logical_data.clone(), u.initial_version, u.updated_version)
        .await
        .context(format!(
            "unable to complete file upgrade from version {} to {}",
            u.initial_version, u.updated_version
        ))?;
    file.logical_data = new_data;

    // Update the version of the file. We don't actually write the changes to disk yet because
    // these updates are recoverable / repeatable at next boot.
    file.version = u.updated_version;
    Ok(())
}

/// perform_file_upgrades will take a file through the upgrade chain.
async fn perform_file_upgrades(
    file: &mut AtomicFile,
    latest_version: u8,
    upgrades: &Vec<Upgrade>,
) -> Result<(), Error> {
    // Execute the upgrades.
    while file.version != latest_version {
        let mut found = false;
        for upgrade in upgrades {
            if upgrade.initial_version == file.version {
                perform_file_upgrade(file, upgrade)
                    .await
                    .context("unable to complete file upgrade")?;
                file.version = upgrade.updated_version;
                found = true;
                break;
            }
        }

        // The upgrades verifier ensures that if an upgrade exists in the set of upgrades, then
        // there also exists a path to the latest_version from that upgrade. Therefore, if this
        // file doesn't have a path to the latest version, no other upgrades will be executed
        // either - at least as long as the upgrade verifier is working.
        if !found {
            panic!("attempting to perform file upgrades without a viable upgrade path");
        }
    }

    Ok(())
}

/// delete_file will delete the atomic file at the given filepath. This will delete both the
/// .atomic_file and the .atomic_file_backup
pub async fn delete_file(filepath: &PathBuf) -> Result<(), Error> {
    let mut main_path = filepath.clone();
    let mut backup_path = filepath.clone();
    add_extension(&mut main_path, "atomic_file");
    async_std::fs::remove_file(main_path.clone()).await.context("unable to backup file")?;
    add_extension(&mut backup_path, "atomic_file_backup");
    async_std::fs::remove_file(backup_path.clone()).await.context("unable to remove main file")?;
    Ok(())
}

/// open_file_v1 is a convenience wrapper for open_file which uses '1' as the version and an empty
/// vector as the upgrade path.
pub async fn open_file_v1(filepath: &PathBuf, expected_identifier: &str) -> Result<AtomicFile, Error> {
    open_file(filepath, expected_identifier, 1, &Vec::new()).await
}

/// open_file will open an atomic file, using the backup of the file if the checksum fails. If the
/// file does not yet exist and no backup file exists, a blank file will be opened. Data will not
/// be written to the blank file until
///
/// If the file does not yet exist, a new file will be created and the file will be empty. The file
/// will automatically be assigned the latest_version. If the file exists but has an outdated
/// version, the upgrades will be used to convert the file to the latest version.
///
/// An error will be returned if the file does exist and has the wrong identifier, or if the file
/// has a version that is higher than 'latest_version', or if the upgrades do not provide a valid
/// path from the current version of the file to the latest version, or if both the file and the
/// backup file are corrupt.
pub async fn open_file(
    filepath: &PathBuf,
    expected_identifier: &str,
    latest_version: u8,
    upgrades: &Vec<Upgrade>,
) -> Result<AtomicFile, Error> {
    // Verify that the inputs match all requirements.
    let path_str = filepath.to_str().context("could not stringify path")?;
    if !path_str.is_ascii() {
        bail!("path should be valid ascii");
    }
    if expected_identifier.len() > 200 {
        bail!("the identifier of an atomic file cannot exceed 200 bytes");
    }
    if !expected_identifier.is_ascii() {
        bail!("the identifier must be ascii");
    }
    if latest_version == 0 {
        bail!("version is not allowed to be zero");
    }

    // Start by opening both the main file and the backup file.
    let mut filepath = filepath.clone();
    let mut backup_filepath = filepath.clone();
    add_extension(&mut filepath, "atomic_file");
    add_extension(&mut backup_filepath, "atomic_file_backup");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(filepath)
        .await
        .context("unable to open versioned file")?;
    let mut backup_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(backup_filepath)
        .await
        .context("unable to open versioned file")?;

    // Get the length of the main file. If the main file doesn't have a length of zero, we need to
    // verify the checksum.
    let file_md = file
        .metadata()
        .await
        .context("unable to get file metadata")?;
    let file_len = file_md.len();
    if file_len >= 4096 {
        println!("opening the file because it seems real");
        let mut buf = vec![0u8; file_len as usize];
        file.read_exact(&mut buf)
            .await
            .context("unable to read file")?;

        let mut hasher = Sha256::new();
        hasher.update(&buf[32..]);
        let result = hasher.finalize();
        if result[..] == buf[..32] {
            let (identifier, version) = identifier_and_version_from_metadata(&buf[..4096])
                .context("unable to parse version and identifier from file metadata")?;
            if identifier != expected_identifier {
                bail!("file has the wrong identifier");
            }
            verify_upgrade_paths(&upgrades, version, latest_version)
                .context("upgrade paths are invalid")?;
            let mut atomic_file = AtomicFile {
                backup_file,
                file,
                identifier,
                logical_data: buf[4096..].to_vec(),
                version,
            };
            perform_file_upgrades(&mut atomic_file, latest_version, upgrades)
                .await
                .context("unable to upgrade file")?;
            return Ok(atomic_file);
        }
    }

    // If we've reached this part of the code, the existing file is either invalid or empty. Try to
    // read from the backup file and see if that is valid.
    let backup_file_md = backup_file
        .metadata()
        .await
        .context("unable to get backup_file metadata")?;
    let backup_file_len = backup_file_md.len();
    if backup_file_len >= 4096 {
        let mut buf = vec![0u8; backup_file_len as usize];
        backup_file
            .read_exact(&mut buf)
            .await
            .context("unable to read backup_file")?;

        let mut hasher = Sha256::new();
        hasher.update(&buf[32..]);
        let result = hasher.finalize();
        if result[..] == buf[..32] {
            let (identifier, version) = identifier_and_version_from_metadata(&buf[..4096])
                .context("unable to parse version and identifier from file metadata")?;
            if identifier != expected_identifier {
                bail!("file has the wrong identifier");
            }
            verify_upgrade_paths(&upgrades, version, latest_version)
                .context("upgrade paths are invalid")?;

            let mut atomic_file = AtomicFile {
                backup_file,
                file,
                identifier,
                logical_data: buf[4096..].to_vec(),
                version,
            };
            perform_file_upgrades(&mut atomic_file, latest_version, upgrades)
                .await
                .context("unable to upgrade file")?;

            // Backup is fine but file is corrupt; we need to write the full data to the main file
            // so that the next change is safe, as the next change will start by overwriting the
            // backup data.
            atomic_file
                .file
                .set_len(buf.len() as u64)
                .await
                .context("unable to set length of atomic file")?;
            atomic_file
                .file
                .seek(SeekFrom::Start(0))
                .await
                .context("unable to seek in atomic file")?;
            atomic_file
                .file
                .write_all(&buf)
                .await
                .context("unable to write backup data to atomic file")?;
            atomic_file
                .file
                .sync_all()
                .await
                .context("unable to sync backup data to atomic file")?;

            return Ok(atomic_file);
        }
    }

    // If the length of the main file is zero after the above checks, we can safely assume that
    // either this is a fully new file, or any data corruption happened during a previous attempt
    // at creating the file, therefore we can treat the file as new.
    if file_len == 0 {
        let mut af = AtomicFile {
            backup_file,
            file,
            identifier: expected_identifier.to_string(),
            logical_data: Vec::new(),
            version: latest_version,
        };
        af.write_file(&Vec::new()).await.context("unable to create new file")?;
        return Ok(af);
    }

    // We should only reach this code if both files have data and are failing the checksum, which
    // indicates unrecoverable corruption. Fail rather than try to make a new file in this case.
    bail!("there appears to have been unrecoverable file corruption");
}

#[cfg(test)]
mod tests {
    use super::*;

    use testdir::testdir;

    // Create a helper function which does a null upgrade so that we can do testing of the upgrade
    // path verifier.
    async fn stub_upgrade(v: Vec<u8>, _: u8, _: u8) -> Result<Vec<u8>, Error> {
        Ok(v)
    }

    // This is a basic upgrade function that expects the current contents of the file to be
    // "test_data". It will alter the contents so that they say "test".
    async fn smoke_upgrade_1_2(
        data: Vec<u8>,
        initial_version: u8,
        updated_version: u8,
    ) -> Result<Vec<u8>, Error> {
        // Verify that the correct version is being used.
        if initial_version != 1 || updated_version != 2 {
            bail!("this upgrade is intended to take the file from version 1 to version 2");
        }
        if data.len() != 9 {
            bail!("file is wrong len");
        }
        if data != b"test_data" {
            bail!(format!("file appears corrupt: {:?}", data));
        }

        // Replace the data with new data.
        Ok(b"test".to_vec())
    }

    // smoke upgrade 2->3
    async fn smoke_upgrade_2_3(
        data: Vec<u8>,
        initial_version: u8,
        updated_version: u8,
    ) -> Result<Vec<u8>, Error> {
        // Verify that the correct version is being used.
        if initial_version != 2 || updated_version != 3 {
            bail!("this upgrade is intended to take the file from version 2 to version 3");
        }
        if data.len() != 4 {
            bail!("file is wrong len");
        }
        if data != b"test" {
            bail!("file appears corrupt");
        }

        // Replace the data with new data.
        Ok(b"testtest".to_vec())
    }

    // smoke upgrade 3->4
    async fn smoke_upgrade_3_4(
        data: Vec<u8>,
        initial_version: u8,
        updated_version: u8,
    ) -> Result<Vec<u8>, Error> {
        // Verify that the correct version is being used.
        if initial_version != 3 || updated_version != 4 {
            bail!("this upgrade is intended to take the file from version 1 to version 2");
        }
        if data.len() != 8 {
            bail!("file is wrong len");
        }
        // Read the file and verify that we are upgrading the correct data.
        if data != b"testtest" {
            bail!("file appears corrupt");
        }

        // Truncate the file and write the new data into it.
        Ok(b"testtesttest".to_vec())
    }

    // Do basic testing of all the major functions for VersionedFiles
    #[async_std::test]
    async fn smoke_test() {
        // Create a basic versioned file.
        let dir = testdir!();
        let test_dat = dir.join("test.dat");
        open_file(&test_dat, "versioned_file::test.dat", 0, &Vec::new())
            .await
            .context("unable to create versioned file")
            .unwrap_err();
        open_file(&test_dat, "versioned_file::test.dat", 1, &Vec::new())
            .await
            .context("unable to create versioned file")
            .unwrap();
        // Try to open it again.
        open_file(&test_dat, "versioned_file::test.dat", 1, &Vec::new())
            .await
            .context("unable to create versioned file")
            .unwrap();
        // Try to open it with the wrong specifier.
        open_file(&test_dat, "bad_versioned_file::test.dat", 1, &Vec::new())
            .await
            .context("unable to create versioned file")
            .unwrap_err();

        // Try to make some invalid new files.
        let invalid_name = dir.join("❄️"); // snowflake emoji in filename
        open_file(&invalid_name, "versioned_file::test.dat", 1, &Vec::new())
            .await
            .context("unable to create versioned file")
            .unwrap_err();
        let invalid_id = dir.join("invalid_identifier.dat");
        open_file(&invalid_id, "versioned_file::test.dat::❄️", 1, &Vec::new())
            .await
            .context("unable to create versioned file")
            .unwrap_err();

        // Perform a test where we open test.dat and write a small amount of data to it. Then we
        // will open the file again and read back that data.
        let mut file = open_file(&test_dat, "versioned_file::test.dat", 1, &Vec::new())
            .await
            .unwrap();
        file.write_file(b"test_data").await.unwrap();
        let file = open_file(&test_dat, "versioned_file::test.dat", 1, &Vec::new())
            .await
            .unwrap();
        if file.len() != 9 {
            panic!("file has unexpected len");
        }
        if &file.contents() != b"test_data" {
            panic!("data read does not match data written");
        }
        // Try to open the file again and ensure the write happened in the correct spot.
        open_file(&test_dat, "versioned_file::test.dat", 1, &Vec::new())
            .await
            .unwrap();

        // Open the file again, this time with an upgrade for smoke_upgrade_1_2.
        let mut upgrade_chain = vec![Upgrade {
            initial_version: 1,
            updated_version: 2,
            process: wrap_upgrade_process(smoke_upgrade_1_2),
        }];
        let file = open_file(&test_dat, "versioned_file::test.dat", 2, &upgrade_chain)
            .await
            .unwrap();
        if file.len() != 4 {
            panic!("file has wrong len");
        }
        if &file.contents() != b"test" {
            panic!("data read does not match data written");
        }
        // Try to open the file again to make sure everything still completes.
        open_file(&test_dat, "versioned_file::test.dat", 2, &upgrade_chain)
            .await
            .unwrap();

        // Attempt to do two upgrades at once, from 2 to 3  and 3 to 4.
        upgrade_chain.push(Upgrade {
            initial_version: 2,
            updated_version: 3,
            process: wrap_upgrade_process(smoke_upgrade_2_3),
        });
        upgrade_chain.push(Upgrade {
            initial_version: 3,
            updated_version: 4,
            process: wrap_upgrade_process(smoke_upgrade_3_4),
        });
        let file = open_file(&test_dat, "versioned_file::test.dat", 4, &upgrade_chain)
            .await
            .unwrap();
        if file.len() != 12 {
            panic!("file has wrong len");
        }
        if &file.contents() != b"testtesttest" {
            panic!("data read does not match data written");
        }
        drop(file);
        // Try to open the file again to make sure everything still completes.
        open_file(&test_dat, "versioned_file::test.dat", 4, &upgrade_chain)
            .await
            .unwrap();

        // Corrupt the data of the file. It should open correctly, and then after opening the
        // corruption should be repaired.
        let mut test_main = test_dat.clone();
        add_extension(&mut test_main, "atomic_file");
        let original_data = std::fs::read(&test_main).unwrap();
        std::fs::write(&test_main, b"file corruption!").unwrap();
        open_file(&test_dat, "versioned_file::test.dat", 4, &upgrade_chain)
            .await
            .unwrap();
        let repaired_data = std::fs::read(&test_main).unwrap();
        assert!(repaired_data == original_data);

        // Try deleting the file. When we open the file again with a new identifier, the new
        // identifier should succeed.
        delete_file(&test_dat).await.unwrap();
        open_file_v1(&test_dat, "versioned_file::test.dat::after_delete")
            .await
            .unwrap();
    }

    #[test]
    // Attempt to provide comprehensive test coverage of the upgrade path verifier.
    fn test_verify_upgrade_paths() {
        // Passing in no upgrades should be fine.
        verify_upgrade_paths(&Vec::new(), 0, 0).unwrap_err(); // 0 is not a legal version
        verify_upgrade_paths(&Vec::new(), 0, 1).unwrap_err(); // 0 is not a legal version
        verify_upgrade_paths(&Vec::new(), 1, 1).unwrap();
        verify_upgrade_paths(&Vec::new(), 2, 2).unwrap();
        verify_upgrade_paths(&Vec::new(), 255, 255).unwrap();

        // Passing in a single upgrade should be okay.
        verify_upgrade_paths(
            &vec![Upgrade {
                initial_version: 1,
                updated_version: 2,
                process: wrap_upgrade_process(stub_upgrade),
            }],
            1,
            2,
        )
        .unwrap();

        // A non-increasing upgrade is not okay.
        verify_upgrade_paths(
            &vec![Upgrade {
                initial_version: 2,
                updated_version: 2,
                process: wrap_upgrade_process(stub_upgrade),
            }],
            2,
            2,
        )
        .unwrap_err();

        // No route to final version is not okay.
        verify_upgrade_paths(
            &vec![Upgrade {
                initial_version: 1,
                updated_version: 2,
                process: wrap_upgrade_process(stub_upgrade),
            }],
            1,
            3,
        )
        .unwrap_err();

        // Simple path is okay.
        verify_upgrade_paths(
            &vec![
                Upgrade {
                    initial_version: 1,
                    updated_version: 2,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
            ],
            1,
            3,
        )
        .unwrap();

        // Two starting options for the same version is not okay.
        verify_upgrade_paths(
            &vec![
                Upgrade {
                    initial_version: 1,
                    updated_version: 2,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 1,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
            ],
            1,
            3,
        )
        .unwrap_err();

        // Two ending options for the same version is okay.
        verify_upgrade_paths(
            &vec![
                Upgrade {
                    initial_version: 1,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
            ],
            1,
            3,
        )
        .unwrap();

        // Two ending options for the same version, version too high.
        verify_upgrade_paths(
            &vec![
                Upgrade {
                    initial_version: 1,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
            ],
            1,
            2,
        )
        .unwrap_err();

        // Complex valid structure.
        verify_upgrade_paths(
            &vec![
                Upgrade {
                    initial_version: 1,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 3,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 4,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 5,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
            ],
            1,
            6,
        )
        .unwrap();

        // Complex valid structure.
        verify_upgrade_paths(
            &vec![
                Upgrade {
                    initial_version: 1,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 3,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 4,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
            ],
            1,
            6,
        )
        .unwrap();

        // Complex valid structure.
        verify_upgrade_paths(
            &vec![
                Upgrade {
                    initial_version: 1,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 3,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 4,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
            ],
            5,
            6,
        )
        .unwrap_err();

        // Complex valid structure, randomly ordered.
        verify_upgrade_paths(
            &vec![
                Upgrade {
                    initial_version: 5,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 3,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 1,
                    updated_version: 3,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 4,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
            ],
            1,
            6,
        )
        .unwrap();

        // Complex structure, randomly ordered, one orphan.
        verify_upgrade_paths(
            &vec![
                Upgrade {
                    initial_version: 2,
                    updated_version: 5,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 6,
                    updated_version: 7,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 3,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 1,
                    updated_version: 4,
                    process: wrap_upgrade_process(stub_upgrade),
                },
                Upgrade {
                    initial_version: 4,
                    updated_version: 6,
                    process: wrap_upgrade_process(stub_upgrade),
                },
            ],
            1,
            6,
        )
        .unwrap_err();
    }

    #[test]
    fn test_version_to_bytes() {
        assert!(&version_to_bytes(1) == b"001\n");
        assert!(&version_to_bytes(2) == b"002\n");
        assert!(&version_to_bytes(9) == b"009\n");
        assert!(&version_to_bytes(10) == b"010\n");
        assert!(&version_to_bytes(39) == b"039\n");
        assert!(&version_to_bytes(139) == b"139\n");
    }
}
