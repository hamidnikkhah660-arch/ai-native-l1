//! Separate zero-value Devnet runtime candidate.
//!
//! The default PTB2/PFS2 runtime is loopback-only unless the explicit `--public-devnet` switch
//! enables authenticated static-peer transport for the zero-value candidate. This transport mode
//! does not provide transactions, a faucet, peer discovery, or Mainnet consensus. QZBE v2 remains
//! a separate opt-in loopback diagnostic subcommand and never migrates legacy stores.

#[path = "private_testnet_node.rs"]
mod private_testnet_node;
#[path = "qzbe_v04_peer_node.rs"]
mod qzbe_v04_peer_node;

fn is_qzbe_v04_subcommand(args: &[String]) -> bool {
    args.first()
        .is_some_and(|arg| arg == "--qzbe-v04-peer-smoke")
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if is_qzbe_v04_subcommand(&args) {
        if let Err(error) =
            qzbe_v04_peer_node::run_from_devnet_dispatch(args.into_iter().skip(1).collect())
        {
            eprintln!(
                "event=devnet_qzbe_v04_dispatch_failed reason={} public_launch_approved=false",
                error.replace(['\r', '\n'], "_")
            );
            std::process::exit(1);
        }
        return;
    }
    private_testnet_node::main_devnet();
}

#[cfg(test)]
mod dispatch_tests {
    use super::is_qzbe_v04_subcommand;

    #[test]
    fn qzbe_mode_requires_the_exact_leading_subcommand() {
        assert!(is_qzbe_v04_subcommand(&[
            "--qzbe-v04-peer-smoke".into(),
            "--help".into()
        ]));
        assert!(!is_qzbe_v04_subcommand(&[
            "--network-id".into(),
            "11".repeat(32)
        ]));
        assert!(!is_qzbe_v04_subcommand(&[
            "--monetary-v4-hybrid-peer-smoke".into()
        ]));
        assert!(!is_qzbe_v04_subcommand(&[]));
    }
}
