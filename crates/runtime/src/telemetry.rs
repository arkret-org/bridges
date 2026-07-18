//! Generic telemetry hooks for bridge layers.

/// Increment a labelled counter when the runtime web recorder is enabled.
pub fn increment_counter(
    name: &'static str,
    labels: impl IntoIterator<Item = (&'static str, String)>,
) {
    #[cfg(feature = "web")]
    {
        let labels = labels
            .into_iter()
            .map(|(key, value)| ::metrics::Label::new(key, value))
            .collect::<Vec<_>>();
        ::metrics::counter!(name, labels).increment(1);
    }
    #[cfg(not(feature = "web"))]
    {
        let _ = (name, labels);
    }
}
