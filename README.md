# pwdb - A simple console based login/password manager

A login/password manager with a basic console interface and local-only
encrypted storage. Uses GnuPG for encryption and verification, leaving all key
management and encrypted file dissemination and synchronization to the
user.

## Requirements

The following are required:

* Rust development toolchain including `rustc` and `cargo`.
* `libgpgme` and the underlying GnuPG utilities (`gpg`, `pinentry`, `gpg-agent`,
etc.)
* Protobuf development tools including the `protoc` compiler, and runtime
library.

## Build and Install

Build and install a release executable with tested dependency versions to
`~/.cargo/bin`:

    ```
    cargo build --release
    cargo test --release
    cargo install --locked --path .
    ```

