//! Fixed host tool paths and bounded process output; no shell interpolation.
use std::{
    io::{self, Read},
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
pub(crate) enum Tool {
    Docker,
    Systemctl,
    Journalctl,
}
pub(crate) struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
}
pub(crate) fn run(tool: Tool, args: &[&str], timeout: Duration) -> io::Result<Output> {
    let executable = match tool {
        Tool::Docker => "/usr/bin/docker",
        Tool::Systemctl => "/usr/bin/systemctl",
        Tool::Journalctl => "/usr/bin/journalctl",
    };
    let mut command = Command::new(executable);
    command.args(args);
    run_command(&mut command, timeout)
}
fn timeout_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "host action outcome requires reconciliation",
    )
}
fn run_command(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env("DOCKER_HOST", "unix:///var/run/docker.sock")
        .env("DOCKER_CONFIG", "/etc/wolf-manager/docker-client")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let pid = rustix::process::Pid::from_raw(child.id() as i32)
        .ok_or_else(|| io::Error::other("invalid child process"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing pipe"))?;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .and_then(|_| {
                if bytes.len() > 1024 * 1024 {
                    Err(io::Error::other("host tool output exceeds bound"))
                } else {
                    Ok(bytes)
                }
            });
        let _ = sender.send(result);
    });
    let (sender, errors) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.send(io::copy(&mut stderr.take(65537), &mut io::sink()));
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            let _ = child.wait();
            return Err(timeout_error());
        }
        thread::sleep(Duration::from_millis(20));
    };
    let collect = || -> io::Result<Output> {
        let stdout = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| timeout_error())??;
        errors
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| timeout_error())??;
        Ok(Output {
            code: status.code(),
            stdout,
        })
    };
    let outcome = collect();
    if outcome.is_err() {
        // The main process may have exited while descendants still own pipes.
        // Stop the process group before returning an uncertain observation.
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    outcome
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    #[test]
    fn reader_timeout_stops_inherited_pipe_descendants() {
        let temporary = tempfile::tempdir().unwrap();
        let marker = temporary.path().join("unexpected-effect");
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "(sleep 0.2; printf late > \"$1\") & exit 0",
            "fixture",
        ]);
        command.arg(&marker);
        let outcome = run_command(&mut command, Duration::from_millis(40));
        assert_eq!(outcome.err().unwrap().kind(), io::ErrorKind::TimedOut);
        thread::sleep(Duration::from_millis(260));
        assert!(
            !marker.exists(),
            "timed-out descendant performed a later effect"
        );
    }
    #[test]
    fn process_output_and_inherited_pipes_remain_bounded() {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "printf exact"]);
        let result = run_command(&mut c, Duration::from_secs(2)).unwrap();
        assert_eq!(result.code, Some(0));
        assert_eq!(result.stdout, b"exact");
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "sleep 0.6 & exit 0"]);
        let before = Instant::now();
        let result = run_command(&mut c, Duration::from_millis(80));
        assert!(before.elapsed() < Duration::from_millis(350));
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
    }
}
