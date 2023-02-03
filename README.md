# atomic-file

The AtomicFile crate provides a wrapper to async\_std::File to enable more convenient and safe
interactions with on-disk data. All operations on AtomicFile are ACID, and the AtomicFile type
includes an invisible 4096 byte header which manages details like version number and file
identifier.

The main use of a version number and file identifier are to provide easy upgrade capabilities
for AtomicFiles, and also to ensure that the wrong file is never being opened.

The main advantage of using an AtomicFile is its ACID compliance, which ensures that data will
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
use atomic_file::open_file_v1;

#[async_std::main]
async fn main() {
    // Create a version 1 file with open_file_v1. If no file exists yet, a new blank file
    // will be created.
    let mut path = PathBuf::new();
    path.push("target");
    path.push("docs-example-1");
    let identifier = "AtomicFileDocs::docs-example-1";
    let mut file = open_file_v1(&path, identifier).await.unwrap();
    // The above call is an alias of 'open_file(&path, identifier, 1, Vec::new())'

    // Use 'contents' and 'write_file' to read and write the logical data of the file. Each
    // one will always read or write the full contents of the file.
    file.write_file(b"hello, world!").await.unwrap();
    let file_data = file.contents();
    if file_data != b"hello, world!" {
        panic!("example did not read correctly");
    }
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
use atomic_file::{open_file, wrap_upgrade_process, AtomicFile, Upgrade};

// An example of a function that upgrades a file from version 1 to version 2, while making
// changes to the body of the file.
async fn example_upgrade(
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
    # let mut f = atomic_file::open_file_v1(&p, i).await.unwrap();
    # f.write_file(b"hello, world!").await.unwrap();
    # drop(f);
    let mut path = PathBuf::new();
    path.push("target");
    path.push("docs-example-2");
    let identifier = "AtomicFileDocs::docs-example-2";
    let upgrade = Upgrade {
        initial_version: 1,
        updated_version: 2,
        process: wrap_upgrade_process(example_upgrade),
    };
    let mut file = open_file(&path, identifier, 2, &vec![upgrade]).await.unwrap();
    // Note that the wrap_upgrade_process call is necessary to create the correct function
    // pointer for the upgrade. Also note that the upgrades are passed in as a vector,
    // allowing the caller to define upgrades for 1 -> 2, 2 -> 3, etc, which will all be
    // called in a chain, such that the call to 'open' does not return until the file
    // has been upgraded all the way to the latest version.
    let file_data = file.contents();
    if file_data != b"hello, update!" {
        panic!("upgrade appears to have failed: \n{:?}\n{:?}", file_data, b"hello, update!");
    }

    // Perform cleanup.
    drop(file);
    atomic_file::delete_file(&path).await.unwrap();
}
```

If you would like to contribute to this crate, the implementation of the 'Upgrade' is
particularly gnarly, owing to me being unable to figure out the best way to approach function
pointers in Rust. If you know of a cleaner or simpler implementation, a pull requeest is warmly
welcomed.
