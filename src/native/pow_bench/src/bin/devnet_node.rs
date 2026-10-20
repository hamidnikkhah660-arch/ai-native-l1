//! Separate zero-value Devnet runtime candidate.
//!
//! This entrypoint shares the tested PTB2/PFS2 node loop while selecting its own QVDN profile,
//! empty Genesis state, manifest and data-store subdirectory. It intentionally remains loopback-only
//! until authenticated peer transport is wired before PTB2 parsing/import.

#[path = "private_testnet_node.rs"]
mod private_testnet_node;

fn main() {
    private_testnet_node::main_devnet();
}
