use ai_native_l1_pow_bench::cp0130_z_transaction_rejection_matrix::export_results;

fn main() {
    if let Err(error) = export_results() {
        eprintln!("CP0130Z_EXPORT_FAIL {}", error.replace(' ', "_"));
        std::process::exit(2);
    }
}
