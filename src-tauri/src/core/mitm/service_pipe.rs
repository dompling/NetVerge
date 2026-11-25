//! Only connect to the local pipe belonging to the observed service core.
//! PID verification is independent of the HTTP request/response.
use super::service_generation::Generation;
use anyhow::{Context, Result, ensure};
use std::{os::windows::io::AsRawHandle, time::Duration};
use tokio::{net::windows::named_pipe::{ClientOptions, NamedPipeClient}, time::{Instant, sleep}};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

pub(crate) async fn open_verified(pipe: &str, generation: Generation, limit: Duration) -> Result<NamedPipeClient> {
    ensure!(pipe.starts_with(r"\\.\pipe\"), "service core pipe is not local");
    let deadline = Instant::now() + limit;
    let stream = loop {
        match ClientOptions::new().open(pipe) {
            Ok(stream) => break stream,
            Err(error) if matches!(error.raw_os_error(), Some(2 | 231)) && Instant::now() < deadline => sleep(Duration::from_millis(100)).await,
            Err(error) => return Err(error).context("open service core pipe"),
        }
    };
    let mut pid = 0u32;
    // SAFETY: the live pipe client owns the handle and the output is a u32.
    let success = unsafe { GetNamedPipeServerProcessId(stream.as_raw_handle() as _, &mut pid) };
    ensure!(success != 0 && pid == generation.pid, "core pipe server PID differs from the authenticated service sample");
    Ok(stream)
}
