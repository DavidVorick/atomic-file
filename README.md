# atomic-file

The AtomicFile crate provides a wrapper to async\_std::File to enable more convenient and safe
interactions with on-disk data. All operations on AtomicFile are ACID, and the AtomicFile type
includes an invisible 4096 byte header which manages details like version number and file
identifier.

The main use of a version number and file identifier are to provide easy upgrade capabilities
for AtomicFiles, and also to ensure that the wrong file is never being opened in the event that
the user incorrectly moved a file from one place to another.

The main advantage of using an AtomicFile is its ACID guarantees, which ensures that data will
never be corrupted in the event of a sudden loss of power. Typical file usage patters leave
users vulnerable to corruption, especially when updating a file. AtomicFile protects against
corruption by using a double-write scheme to guarantee that correct data exists on disk, and
uses a checksum to verify at startup that the correct instance of the doubly-written file is
loaded. This does mean that two files will exist on disk for each AtomicFile - a .atomic\_file
and a .atomic\_file\_backup.

Data corruption can still occur in the event of something extreme like physical damage to the
hard drive, but changes of recovery are better and the user is protected against all common
forms of corruption (which stem from power being lost unexpectedly).

The 'Atomic' property of the AtomicFile is that the only read and write operations fully read
or fully write the file.
```rs
// Basic file operations

use std::path::PathBuf;
use atomic_file::{
    open, open_file,
    OpenSettings::CreateIfNotExists,
};

#[async_std::main]
async fn main() {
    // Create a version 1 file with open_file. We pass in an empty vector for the upgrade path,
    // and 'CreateIfNotExists' to indicate that we want to create the non-existing file.
    let mut path = PathBuf::new();
    path.push("target");
    path.push("docs-example-1");
    let identifier = "AtomicFileDocs::docs-example-1";
    let mut file = open_file(&path, identifier, 1, &Vec::new(), CreateIfNotExists).await.unwrap();

    // Use 'contents' and 'write_file' to read and write the logical data of the file. Each
    // one will always read or write the full contents of the file.
    file.write_file(b"hello, world!").await.unwrap();
    let file_data = file.contents();
    if file_data != b"hello, world!" {
        panic!("example did not read correctly");
    }
    drop(file);

    // Now that we have created a file, we can use 'open(path, identifier)' as an alias for:
    // 'open_file(path, identifier, 1, Vec::new(), ErrorIfNotExists)'
    let file = open(&path, identifier);
    # drop(file);
    # atomic_file::delete_file(&path).await.unwrap();
}
```
AtomicFile uses a versioning and upgrading scheme to simplify the process of releasing new
versions of a file. When opening a file, you pass in a version number and an upgrade path which
will allow the file opening process to automatically upgrade your files from their current
version to the latest version.
```rs
// Simple upgrade example
use std::path::PathBuf;

use anyhow::{bail, Result, Error};
use atomic_file::{open, open_file, AtomicFile, Upgrade};
use atomic_file::OpenSettings::ErrorIfNotExists;
# use atomic_file::OpenSettings::CreateIfNotExists;

// An example of a function that upgrades a file from version 1 to version 2, while making
// changes to the body of the file.
fn example_upgrade(
    data: Vec<u8>,
    initial_version: u8,
    updated_version: u8,
) -> Result<Vec<u8>, Error> {
    // Check that the version is okay.
    if initial_version != 1 || updated_version != 2 {
        bail!("wrong version");
    }

    // Return updated contents for the file.
    Ok((b"hello, update!".to_vec()))
}

#[async_std::main]
async fn main() {
    # let mut p = PathBuf::new();
    # p.push("target");
    # p.push("docs-example-2");
    # let i = "AtomicFileDocs::docs-example-2";
    # let mut f = atomic_file::open_file(&p, i, 1, &Vec::new(), CreateIfNotExists).await.unwrap();
    # f.write_file(b"hello, world!").await.unwrap();
    # drop(f);
    let mut path = PathBuf::new();
    path.push("target");
    path.push("docs-example-2");
    let identifier = "AtomicFileDocs::docs-example-2";
    let upgrade = Upgrade {
        initial_version: 1,
        updated_version: 2,
        process: example_upgrade,
    };
    let mut file = open_file(&path, identifier, 2, &vec![upgrade], ErrorIfNotExists).await.unwrap();
    // Note that the upgrades are passed in as a vector, allowing the caller to
    // define entire upgrade chains, e.g. 1->2 and 2->3. The final file that gets returned
    // will have been upgraded through the chain to the latest version.
    let file_data = file.contents();
    if file_data != b"hello, update!" {
        panic!("upgrade appears to have failed: \n{:?}\n{:?}", file_data, b"hello, update!");
    }

    // Perform cleanup.
    drop(file);
    atomic_file::delete_file(&path).await.unwrap();
}
```

If you would like to contribute to this crate, we are looking for a way to make the upgrade
functions async+Send as prior attempts were unsuccessful.
