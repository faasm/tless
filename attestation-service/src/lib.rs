use env_logger::{Builder, Env};
use log::LevelFilter;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn init_logging() {
    INIT.call_once(|| {
        let env = Env::default().filter_or("RUST_LOG", "info");
        let mut builder = Builder::from_env(env);

        // Disable noisy modules.
        let noisy_modules: Vec<&str> = vec!["hickory_proto", "hyper_util", "hyper", "reqwest"];
        for module in &noisy_modules {
            builder.filter_module(module, LevelFilter::Off);
        }

        builder.init();
    });
}
