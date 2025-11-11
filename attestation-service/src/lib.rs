use env_logger::Env;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn init_logging(is_test: bool) {
    INIT.call_once(|| {
        let _ = env_logger::Builder::from_env(
            Env::default().default_filter_or("error,attestation_service=info,accli=info"),
        )
        .is_test(is_test)
        .try_init();
    });
}
