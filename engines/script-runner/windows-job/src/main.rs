// A trusted, Windows-only launcher. It accepts no shell command, only a Node
// executable, a runner file and a bounded deadline from the trusted parent.
#[cfg(windows)]
mod windows_job {
    use std::{
        io,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        path::PathBuf,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        },
        Threading::GetCurrentProcess,
    };

    const JOB_MEMORY_BYTES: usize = 256 * 1024 * 1024;
    const MAX_JOB_PROCESSES: u32 = 2;
    const FAILURE: i32 = 125;
    const TIMEOUT: i32 = 124;

    fn join_job() -> io::Result<()> {
        // SAFETY: null attributes/name create an unnamed, non-inheritable handle.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateJobObjectW returned a fresh owned handle.
        let job = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_JOB_MEMORY;
        limits.BasicLimitInformation.ActiveProcessLimit = MAX_JOB_PROCESSES;
        limits.JobMemoryLimit = JOB_MEMORY_BYTES;
        // SAFETY: the handle and fixed-size input buffer remain valid during the call.
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Join BEFORE any child is created. All descendants inherit this job.
        // No breakaway flags are enabled; a failed nested assignment fails closed.
        // SAFETY: the job is valid and GetCurrentProcess returns the current pseudo-handle.
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), GetCurrentProcess()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Keep the sole handle open until this launcher exits or is terminated.
        // The OS then closes it and kills remaining job members. Do not drop it
        // while we are still inside the kill-on-close job ourselves.
        std::mem::forget(job);
        Ok(())
    }

    pub fn run() -> i32 {
        let mut args = std::env::args_os().skip(1);
        let (Some(node), Some(script), Some(timeout)) = (args.next(), args.next(), args.next()) else {
            return FAILURE;
        };
        let (node, script) = (PathBuf::from(node), PathBuf::from(script));
        let Some(ms) = timeout.to_str().and_then(|s| s.parse::<u64>().ok()) else {
            return FAILURE;
        };
        if args.next().is_some() || !node.is_absolute() || !script.is_absolute() || !(50..=6500).contains(&ms) {
            return FAILURE;
        }
        let deadline = Instant::now() + Duration::from_millis(ms);
        if join_job().is_err() {
            return FAILURE;
        }
        let mut command = Command::new(node);
        command.arg("--max-old-space-size=64").arg(script)
            .stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::null());
        // The parent already supplies a minimal environment. Independently strip
        // everything other than the Windows startup variables here as well.
        command.env_clear();
        for name in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let Ok(mut child) = command.spawn() else {
            return FAILURE;
        };
        loop {
            if Instant::now() >= deadline {
                return TIMEOUT;
            }
            match child.try_wait() {
                Ok(Some(status)) => return if status.success() { 0 } else { FAILURE },
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => return FAILURE,
            }
        }
    }
}

#[cfg(windows)]
fn main() {
    std::process::exit(windows_job::run());
}

#[cfg(not(windows))]
fn main() {
    std::process::exit(125);
}
