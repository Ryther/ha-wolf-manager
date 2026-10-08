//! Product-only structured logging; dependency diagnostics can contain private payloads.
use tracing_subscriber::{EnvFilter, fmt::MakeWriter, prelude::*};

pub fn subscriber<W>(writer: W, filter: EnvFilter) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::registry().with(filter).with(
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(writer)
            .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                metadata.target() == "ha_wolf_manager"
                    || metadata.target().starts_with("ha_wolf_manager::")
            })),
    )
}

pub fn initialize() -> Result<(), wolf_core::SafeError> {
    subscriber(
        std::io::stderr,
        EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
    )
    .try_init()
    .map_err(|_| wolf_core::SafeError::new("internal_error"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };
    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl<'a> MakeWriter<'a> for Buffer {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }
    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn trace_filter_never_enables_dependency_payload_logs() {
        let buffer = Buffer::default();
        let output = buffer.clone();
        tracing::subscriber::with_default(subscriber(buffer, EnvFilter::new("trace")), || {
            tracing::info!(target:"ha_wolf_manager::runtime",code="ready","Controlled product event");
            tracing::trace!(target:"reqwest::connect",host="synthetic-private-endpoint","Dependency connection event");
            tracing::error!(target:"russh::client",raw="synthetic-private-payload","Dependency payload event");
        });
        let bytes = output.0.lock().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("Controlled product event"));
        assert!(!text.contains("synthetic-private"));
        assert!(!text.contains("Dependency"));
    }
}
