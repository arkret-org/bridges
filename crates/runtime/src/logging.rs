//! tracing initialization.

use crate::config::LoggingConfig;

/// Initialize the global tracing subscriber from the configuration. Safe to
/// call repeatedly (errors are ignored).
pub fn init(cfg: &LoggingConfig) {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.level));

    let builder = fmt().with_env_filter(filter);
    let _ = if cfg.format == "json" {
        builder.json().try_init()
    } else {
        builder.try_init()
    };
}
