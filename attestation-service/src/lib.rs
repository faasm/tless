use env_logger::Env;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn init_logging(is_test: bool) {
    INIT.call_once(|| {
        let default_filter = if is_test {
            // In tests, be more chatty by default.
            "info,attestation_service=info,accli=info"
        } else {
            // In normal runs, keep everything else at error.
            "error,attestation_service=info,accli=info"
        };

        let _ = env_logger::Builder::from_env(
            Env::default().default_filter_or(default_filter),
        )
        .is_test(is_test)
        .try_init();
    });
}
