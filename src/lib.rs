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
//! for AtomicFiles, and also to ensure that the wrong file is never being opened in the event that
//! the user incorrectly moved a file from one place to another.
//!
//! The main advantage of using an AtomicFile is its ACID guarantees, which ensures that data will
//! never be corrupted in the event of a sudden loss of power. Typical file usage patters leave
//! users vulnerable to corruption, especially when updating a file. AtomicFile protects against
//! corruption by using a double-write scheme to guarantee that correct data exists on disk, and
//! uses a checksum to verify at startup that the correct instance of the doubly-written file is
//! loaded. This does mean that two files will exist on disk for each AtomicFile - a .atomic_file
//! and a .atomic_file_backup.
//!
//! The checksum used by an AtomicFile is 6 bytes. We use a 6 byte checksum because our threat
//! model is arbitrary disk failure, not a human adversary. A human adversary could write any
//! checksum they want to defeat our corruption detection. The checksum is written as hex in the
//! first 12 bytes of the file.
//!
//! If a file needs to be manually modified, the checksum can be overwritten. Change the checksum
//! to 'ffffffffffff' (12 chars) and the checksum will be accepted independent of the file
//! contents. The checks for the identifier will still trigger.
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
//! use atomic_file::{
//!     open, open_file,
//!     OpenSettings::CreateIfNotExists,
//! };
//!
//! #[async_std::main]
//! async fn main() {
//!     // Create a version 1 file with open_file. We pass in an empty vector for the upgrade path,
//!     // and 'CreateIfNotExists' to indicate that we want to create the non-existing file.
//!     let mut path = PathBuf::new();
//!     path.push("target");
//!     path.push("docs-example-1");
//!     let identifier = "AtomicFileDocs::docs-example-1";
//!     let mut file = open_file(&path, identifier, 1, &Vec::new(), CreateIfNotExists).await.unwrap();
//!
//!     // Use 'contents' and 'write_file' to read and write the logical data of the file. Each
//!     // one will always read or write the full contents of the file.
//!     file.write_file(b"hello, world!").await.unwrap();
//!     let file_data = file.contents();
//!     if file_data != b"hello, world!" {
//!         panic!("example did not read correctly");
//!     }
//!     drop(file);
//!
//!     // Now that we have created a file, we can use 'open(path, identifier)' as an alias for:
//!     // 'open_file(path, identifier, 1, Vec::new(), ErrorIfNotExists)'
//!     let file = open(&path, identifier);
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
//! use atomic_file::{open, open_file, AtomicFile, Upgrade};
//! use atomic_file::OpenSettings::ErrorIfNotExists;
//! # use atomic_file::OpenSettings::CreateIfNotExists;
//!
//! // An example of a function that upgrades a file from version 1 to version 2, while making
//! // changes to the body of the file.
//! fn example_upgrade(
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
//!     # let mut f = atomic_file::open_file(&p, i, 1, &Vec::new(), CreateIfNotExists).await.unwrap();
//!     # f.write_file(b"hello, world!").await.unwrap();
//!     # drop(f);
//!     let mut path = PathBuf::new();
//!     path.push("target");
//!     path.push("docs-example-2");
//!     let identifier = "AtomicFileDocs::docs-example-2";
//!     let upgrade = Upgrade {
//!         initial_version: 1,
//!         updated_version: 2,
//!         process: example_upgrade,
//!     };
//!     let mut file = open_file(&path, identifier, 2, &vec![upgrade], ErrorIfNotExists).await.unwrap();
//!     // Note that the upgrades are passed in as a vector, allowing the caller to
//!     // define entire upgrade chains, e.g. 1->2 and 2->3. The final file that gets returned
//!     // will have been upgraded through the chain to the latest version.
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
//! If you would like to contribute to this crate, we are looking for a way to make the upgrade
//! functions async+Send as prior attempts were unsuccessful.

use async_std::{
    fs::{File, OpenOptions},
    io::prelude::SeekExt,
    io::{ReadExt, SeekFrom, WriteExt},
};
use std::{
    collections::HashMap,
    path::PathBuf,
    str::from_utf8,
};

use anyhow::{bail, Context, Error, Result};
use sha2::{Digest, Sha256};

/// OpenSettings provides the two options for opening a file in the event that the file does not
/// exist: create the file and return an error.
pub enum OpenSettings {
    /// A new file will be created if the file does not exist.
    CreateIfNotExists,

    /// An error will be returned if the file does not exist.
    ErrorIfNotExists,
}

/// UpgradeFunc defines the signature for a function that can be used to upgrade an
/// AtomicFile. The UpgradeFunc function will receive the file data that needs to be upgraded along
/// with the intended initial version and final version that is expected from the upgrade.
///
/// We pass in the initial version and final version as arguments to provide an extra level of
/// redundancy and to prevent mistakes when copy-pasting upgrades, as an incorrect upgrade could
/// corrupt user data.
pub type UpgradeFunc =
    fn(data: Vec<u8>, initial_version: u8, upgraded_version: u8) -> Result<Vec<u8>, Error>;

/// Upgrade defines an upgrade process for upgrading the data in a file from one version to
/// another.
pub struct Upgrade {
    /// initial_version designates the version of the file that this upgrade should be applied to.
    pub initial_version: u8,
    /// updated_version designates the version of the file after the upgrade is complete.
    pub updated_version: u8,
    /// process defines the function that is used to upgrade the file.
    pub process: UpgradeFunc,
}

/// AtompicFile defines the main type for the crate, and implements an API for safely
/// handling atomic files. The API is based on the async_std::File interface, but with some
/// adjustments that are designed to make it both safer and more ergonomic.
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
        from_utf8(&metadata[13..16]).context("the on-disk version could not be parsed")?;
    let version: u8 = version_str
        .parse()
        .context("unable to parse version of metadata")?;

    let mut clean_identifier = false;
    let mut identifier = "".to_string();
    let mut atomic_identifier_offset = 0;
    for i in 0..201 {
        if metadata[i + 17] == '\n' as u8 {
            clean_identifier = true;
            atomic_identifier_offset = i + 18;
            break;
        }
        if metadata[i + 17] > 127 {
            bail!("identifier contains non-ascii characters before termination sequence");
        }
        identifier.push(metadata[i + 17] as char);
    }
    if !clean_identifier {
        bail!("provided metadata does not have a legally terminating identifier");
    }
    let atomic_identifier = "DavidVorick/atomic_file-v1\n".as_bytes();
    if metadata[atomic_identifier_offset..atomic_identifier_offset+27] != atomic_identifier[..] {
        bail!("file does not appear to be an atomic file");
    }

    Ok((identifier, version))
}

impl AtomicFile {
    /// fill_metadata will write the first 4096 bytes to contain the proper metadata for the file,
    /// including the first 64 bytes which serve as the checksum.
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
        buf[12] = '\n' as u8;
        buf[13..17].copy_from_slice(&version_bytes);
        let iden_bytes = self.identifier.as_bytes();
        buf[17..17 + iden_bytes.len()].copy_from_slice(iden_bytes);
        buf[17 + iden_bytes.len()] = '\n' as u8;
        buf[18 + iden_bytes.len()] = 255; // newline+255 is the termination sequence for identifier
        let atomic_identifier = "DavidVorick/atomic_file-v1\n".as_bytes();
        buf[18 + iden_bytes.len()..18 + iden_bytes.len() + 27].copy_from_slice(atomic_identifier);
        buf[4095] = '\n' as u8;

        // Grab the checksum of the data and fill it in as the first 64 bytes.
        let mut hasher = Sha256::new();
        hasher.update(&buf[12..]);
        let result = hasher.finalize();
        let result_hex = hex::encode(result);
        buf[..12].copy_from_slice(result_hex[..12].as_bytes());
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

/// exists will return whether or not an atomic file is considered to exist on disk.
pub fn exists(filepath: &PathBuf) -> bool {
    let mut path = filepath.clone();
    add_extension(&mut path, "atomic_file");
    path.exists()
}

/// open is a convenience wrapper for open_file which uses '1' as the version, an empty vector as
/// the upgrade path, and ErrorIfNotExists as the open setting.
pub async fn open(filepath: &PathBuf, expected_identifier: &str) -> Result<AtomicFile, Error> {
    open_file(filepath, expected_identifier, 1, &Vec::new(), OpenSettings::ErrorIfNotExists).await
}

/// open_file will open an atomic file, using the backup of the file if the checksum fails. If
/// 'create_if_not_exists' is set to 'true', a new file empty file will be created if a file does
/// not already exist.
///
/// If the version of the file on-disk is outdated, the upgrades will be used in a chain to upgrade
/// the file to the latest version. If no valid path exists from the file's current version to the
/// latest version, an error will be returned.
///
/// An error will also be returned if the file has the wrong identifier, or if it is determined
/// that both the file and its backup are corrupt. Both files should only be corrupt in the event
/// of significant physical damage to the storage device.
pub async fn open_file(
    filepath: &PathBuf,
    expected_identifier: &str,
    latest_version: u8,
    upgrades: &Vec<Upgrade>,
    open_settings: OpenSettings,
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
    // Check that the identifier doesn't contain a newline.
    for c in expected_identifier.chars() {
        if c == '\n' {
            bail!("identifier is not allowed to contain newlines");
        }
    }

    // Parse the enum.
    let create_if_not_exists = match open_settings {
        OpenSettings::CreateIfNotExists => true,
        OpenSettings::ErrorIfNotExists => false,
    };

    // Build the paths for the main file and the backup file.
    let mut filepath = filepath.clone();
    let mut backup_filepath = filepath.clone();
    add_extension(&mut filepath, "atomic_file");
    add_extension(&mut backup_filepath, "atomic_file_backup");
    let filepath_exists = filepath.exists();

    // If the 'create' flag is not set and the main file does not exist, exit with a does not exist
    // error. We don't care about the backup file in this case, beacuse if the main file wasn't
    // even created we can assume the file is missing.
    if !create_if_not_exists && !filepath_exists {
        bail!("file does not exist");
    }

    // If the main file does exist, then we should be able to rely on the assumption that either
    // the main file is not corrupt, or the backup file is not corrupt. If the
    // 'create_if_not_exists' flag has been set, we'll create a blank file which will fail the
    // checksum, and then a blank backup will be created with a failed checksum, and then the user
    // will receive a blank file that's created and ready for them to modify.
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

    // Read the contents of the main file and verify the checksum.
    let file_md = file
        .metadata()
        .await
        .context("unable to get file metadata")?;
    let file_len = file_md.len();
    if file_len >= 4096 {
        let mut buf = vec![0u8; file_len as usize];
        file.read_exact(&mut buf)
            .await
            .context("unable to read file")?;

        let mut hasher = Sha256::new();
        hasher.update(&buf[12..]);
        let result = hasher.finalize();
        let result_hex = hex::encode(result);
        let result_hex_bytes = result_hex.as_bytes();

        // If the file needs to be manually modified for some reason, the hash will no longer work.
        // By changing the checksum to all 'fffff...', the user/developer is capable of overriding
        // the checksum.
        let override_value = [255u8; 6];
        let override_hex = hex::encode(override_value);
        let override_hex_bytes = override_hex.as_bytes();

        // If the checksum passes, perform any required updates on the file and pass the file along to
        // the user.
        if result_hex_bytes[..12] == buf[..12] || buf[..12] == override_hex_bytes[..] {
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

    // If we got this far, the main file exists but was either corrupt or had no data in it. We
    // check the backup file now.
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
        hasher.update(&buf[12..]);
        let result = hasher.finalize();
        let result_hex = hex::encode(result);
        let result_hex_bytes = result_hex.as_bytes();

        // If the checksum passes, perform any required updates on the file and pass the file along to
        // the user.
        if result_hex_bytes[..12] == buf[..12] {
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

    // If we got this far, we either have a new file or a corrupt file. If the length of the main
    // file is '0', we assume it's a new file. If the main file has a size of 0 and the backup file
    // is corrupt, this is still equivalent to having no file at all as it means the file creation
    // process got interrupted before it completed.
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

    use std::io::{Seek, Write};
    use testdir::testdir;
    use OpenSettings::{
        CreateIfNotExists,
        ErrorIfNotExists,
    };

    // Create a helper function which does a null upgrade so that we can do testing of the upgrade
    // path verifier.
    fn stub_upgrade(v: Vec<u8>, _: u8, _: u8) -> Result<Vec<u8>, Error> {
        Ok(v)
    }

    // This is a basic upgrade function that expects the current contents of the file to be
    // "test_data". It will alter the contents so that they say "test".
    fn smoke_upgrade_1_2(
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

    fn smoke_upgrade_2_3(
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

    fn smoke_upgrade_3_4(
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
    async fn smoke_test() {
        // Create a basic versioned file.
        let dir = testdir!();
        let test_dat = dir.join("test.dat");
        open_file(&test_dat, "versioned_file::test.dat", 0, &Vec::new(), CreateIfNotExists)
            .await
            .context("unable to create versioned file")
            .unwrap_err();
        open_file(&test_dat, "versioned_file::test.dat", 1, &Vec::new(), CreateIfNotExists)
            .await
            .context("unable to create versioned file")
            .unwrap();
        // Try to open it again.
        open_file(&test_dat, "versioned_file::test.dat", 1, &Vec::new(), CreateIfNotExists)
            .await
            .context("unable to create versioned file")
            .unwrap();
        // Try to open it with the wrong specifier.
        open_file(&test_dat, "bad_versioned_file::test.dat", 1, &Vec::new(), CreateIfNotExists)
            .await
            .context("unable to create versioned file")
            .unwrap_err();

        // Try to make some invalid new files.
        let invalid_name = dir.join("❄️"); // snowflake emoji in filename
        open_file(&invalid_name, "versioned_file::test.dat", 1, &Vec::new(), CreateIfNotExists)
            .await
            .context("unable to create versioned file")
            .unwrap_err();
        let invalid_id = dir.join("invalid_identifier.dat");
        open_file(&invalid_id, "versioned_file::test.dat::❄️", 1, &Vec::new(), CreateIfNotExists)
            .await
            .context("unable to create versioned file")
            .unwrap_err();

        // Perform a test where we open test.dat and write a small amount of data to it. Then we
        // will open the file again and read back that data.
        let mut file = open_file(&test_dat, "versioned_file::test.dat", 1, &Vec::new(), CreateIfNotExists)
            .await
            .unwrap();
        file.write_file(b"test_data").await.unwrap();
        let file = open_file(&test_dat, "versioned_file::test.dat", 1, &Vec::new(), CreateIfNotExists)
            .await
            .unwrap();
        if file.contents().len() != 9 {
            panic!("file has unexpected len");
        }
        if &file.contents() != b"test_data" {
            panic!("data read does not match data written");
        }
        // Try to open the file again and ensure the write happened in the correct spot.
        open_file(&test_dat, "versioned_file::test.dat", 1, &Vec::new(), CreateIfNotExists)
            .await
            .unwrap();

        // Open the file again, this time with an upgrade for smoke_upgrade_1_2.
        let mut upgrade_chain = vec![Upgrade {
            initial_version: 1,
            updated_version: 2,
            process: smoke_upgrade_1_2,
        }];
        let file = open_file(&test_dat, "versioned_file::test.dat", 2, &upgrade_chain, CreateIfNotExists)
            .await
            .unwrap();
        if file.contents().len() != 4 {
            panic!("file has wrong len");
        }
        if &file.contents() != b"test" {
            panic!("data read does not match data written");
        }
        // Try to open the file again to make sure everything still completes.
        open_file(&test_dat, "versioned_file::test.dat", 2, &upgrade_chain, CreateIfNotExists)
            .await
            .unwrap();

        // Attempt to do two upgrades at once, from 2 to 3  and 3 to 4.
        upgrade_chain.push(Upgrade {
            initial_version: 2,
            updated_version: 3,
            process: smoke_upgrade_2_3,
        });
        upgrade_chain.push(Upgrade {
            initial_version: 3,
            updated_version: 4,
            process: smoke_upgrade_3_4,
        });
        let file = open_file(&test_dat, "versioned_file::test.dat", 4, &upgrade_chain, CreateIfNotExists)
            .await
            .unwrap();
        if file.contents().len() != 12 {
            panic!("file has wrong len");
        }
        if &file.contents() != b"testtesttest" {
            panic!("data read does not match data written");
        }
        drop(file);
        // Try to open the file again to make sure everything still completes.
        open_file(&test_dat, "versioned_file::test.dat", 4, &upgrade_chain, CreateIfNotExists)
            .await
            .unwrap();

        // Corrupt the data of the file. It should open correctly, and then after opening the
        // corruption should be repaired.
        let mut test_main = test_dat.clone();
        add_extension(&mut test_main, "atomic_file");
        let original_data = std::fs::read(&test_main).unwrap();
        std::fs::write(&test_main, b"file corruption!").unwrap();
        open_file(&test_dat, "versioned_file::test.dat", 4, &upgrade_chain, CreateIfNotExists)
            .await
            .unwrap();
        let repaired_data = std::fs::read(&test_main).unwrap();
        assert!(repaired_data == original_data);

        // Try modifying the checksum of the file to see if it still completes. We modify the raw
        // data as well to see if the backup loads.
        let mut raw_file_name = test_dat.clone();
        add_extension(&mut raw_file_name, "atomic_file");
        println!("{:?}", raw_file_name);
        let mut raw_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(raw_file_name)
            .unwrap();
        raw_file.set_len(4096).unwrap();
        raw_file.write("ffff".as_bytes()).unwrap();

        // Try to open the file with a bad checksum and make sure it fails.
        let shorter_file = open_file(&test_dat, "versioned_file::test.dat", 4, &upgrade_chain, CreateIfNotExists)
            .await
            .unwrap();
        assert!(shorter_file.contents().len() != 0); // should be the original file

        // Write out the full checksum override then see that the file still opens.
        raw_file.set_len(4096).unwrap();
        raw_file.seek(std::io::SeekFrom::Start(0)).unwrap();
        raw_file.write("ffffffffffff".as_bytes()).unwrap();
        let shorter_file = open(&test_dat, "versioned_file::test.dat")
            .await
            .unwrap();
        assert!(shorter_file.contents().len() == 0); // should accept the manually modified file

        // Try deleting the file. When we open the file again with a new identifier, the new
        // identifier should succeed.
        delete_file(&test_dat).await.unwrap();
        open_file(&test_dat, "versioned_file::test.dat::after_delete", 1, &Vec::new(), CreateIfNotExists)
            .await
            .unwrap();

        // Delete the file again, then try to open it with 'create_if_not_exists' set to false. The
        // file should not be created, which means it'll fail on subsequent opens as well. We also
        // sneak in a few checks of 'open()'
        assert!(exists(&test_dat));
        open(&test_dat, "versioned_file::test.dat::after_delete").await.unwrap();
        delete_file(&test_dat).await.unwrap();
        open(&test_dat, "versioned_file::test.dat::after_delete").await.unwrap_err();
        assert!(!exists(&test_dat));
        open_file(&test_dat, "versioned_file::test.dat::after_delete", 1, &Vec::new(), ErrorIfNotExists)
            .await
            .unwrap_err();
        open_file(&test_dat, "versioned_file::test.dat::after_delete", 1, &Vec::new(), ErrorIfNotExists)
            .await
            .unwrap_err();

        // Leave one file in the testdir so it can be viewed later.
        let mut f = open_file(&test_dat, "versioned_file::test.dat::after_delete", 1, &Vec::new(), CreateIfNotExists)
            .await
            .unwrap();
        f.write_file("this is where the real file data is stored!".as_bytes()).await.unwrap();
    }

    #[async_std::test]
    async fn smoke_test_async_std() {
        smoke_test().await;
    }

    #[tokio::test]
    async fn smoke_test_tokio() {
        smoke_test().await;
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
                process: stub_upgrade,
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
                process: stub_upgrade,
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
                process: stub_upgrade,
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
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: stub_upgrade,
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
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 1,
                    updated_version: 3,
                    process: stub_upgrade,
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
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: stub_upgrade,
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
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: stub_upgrade,
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
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 3,
                    updated_version: 6,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 4,
                    updated_version: 6,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 5,
                    updated_version: 6,
                    process: stub_upgrade,
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
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 3,
                    updated_version: 6,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 4,
                    updated_version: 6,
                    process: stub_upgrade,
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
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 3,
                    updated_version: 6,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 4,
                    updated_version: 6,
                    process: stub_upgrade,
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
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 2,
                    updated_version: 3,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 3,
                    updated_version: 6,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 1,
                    updated_version: 3,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 4,
                    updated_version: 6,
                    process: stub_upgrade,
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
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 6,
                    updated_version: 7,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 3,
                    updated_version: 6,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 1,
                    updated_version: 4,
                    process: stub_upgrade,
                },
                Upgrade {
                    initial_version: 4,
                    updated_version: 6,
                    process: stub_upgrade,
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
