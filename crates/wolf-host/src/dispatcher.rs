//! Unprivileged admission boundary for the fixed, no-argument sudo helper.
use std::{
    io::{self, Read, Write},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use wolf_core::{RPC_MAX_BYTES, RpcRequest, RpcResponse, canonical_json};
const OUTPUT_LIMIT: usize = 1024 * 1024;
fn refused() -> io::Error {
    io::Error::other("restricted RPC refused")
}
pub fn dispatch<R: Read, F: FnOnce(&[u8]) -> io::Result<Vec<u8>>>(
    original: &str,
    mut input: R,
    helper: F,
) -> io::Result<Vec<u8>> {
    if original != "wolf-manager-rpc-v1" {
        return Err(refused());
    }
    let mut bytes = Vec::new();
    (&mut input)
        .take((RPC_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let request = RpcRequest::parse(&bytes).map_err(|_| refused())?;
    let output = helper(&canonical_json(&request).map_err(|_| refused())?)?;
    if output.len() > OUTPUT_LIMIT {
        return Err(refused());
    }
    let reply: RpcResponse = serde_json::from_slice(&output).map_err(|_| refused())?;
    reply.validate_for(&request).map_err(|_| refused())?;
    canonical_json(&reply).map_err(|_| refused())
}
/// Paths and argv are constant; caller bytes travel only on validated stdin.
/// A timeout never proves non-execution: the privileged journal remains authority.
pub fn fixed_helper(bytes: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    if bytes.len() > RPC_MAX_BYTES {
        return Err(refused());
    }
    let mut command = Command::new("/usr/bin/sudo");
    command
        .args(["-n", "/usr/libexec/wolf-manager/wolf-host-root"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_helper(&mut command, bytes, timeout)
}
fn run_helper(command: &mut Command, bytes: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().ok_or_else(refused)?;
    let request = bytes.to_vec();
    let (writer_tx, writer) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = writer_tx.send(stdin.write_all(&request));
    });
    let stdout = child.stdout.take().ok_or_else(refused)?;
    let (reader_tx, reader) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = (|| {
            let mut bytes = Vec::new();
            stdout
                .take((OUTPUT_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > OUTPUT_LIMIT {
                Err(refused())
            } else {
                Ok(bytes)
            }
        })();
        let _ = reader_tx.send(result);
    });
    let stderr = child.stderr.take().ok_or_else(refused)?;
    // Discard bounded stderr; private diagnostics never enter protocol responses.
    let (errors_tx, errors) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = errors_tx.send(io::copy(&mut stderr.take(65537), &mut io::sink()));
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            // Sudo may already have elevated; best-effort kill is not rollback.
            // Detached readers stay bounded and the helper may finish its journal.
            let _ = child.kill();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "RPC outcome requires journal reconciliation",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    receive_until(writer, deadline)??;
    receive_until(errors, deadline)??;
    if !matches!(status.code(), Some(0 | 1)) {
        return Err(refused());
    }
    receive_until(reader, deadline)?
}

fn receive_until<T>(receiver: mpsc::Receiver<T>, deadline: Instant) -> io::Result<T> {
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "RPC outcome requires journal reconciliation",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inherited_pipe_cannot_extend_request_deadline() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 0.6 & exit 0"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let result = run_helper(&mut command, b"", Duration::from_millis(80));
        assert!(
            started.elapsed() < Duration::from_millis(350),
            "pipe extended deadline"
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
