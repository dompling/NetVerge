use crate::{open_fixture, service_generation::Generation, service_pipe};
use anyhow::{Context, Result, ensure};
use clash_verge_service_ipc::{OWNER_TOKEN_FILE_NAME, OwnerCredentials, OwnerIdentity, mihomo_ipc_path};
use std::{ffi::c_void, os::windows::io::AsRawHandle, path::{Path, PathBuf}, ptr::null_mut, time::Duration};
use windows_sys::Win32::{
    Foundation::{GENERIC_ALL, HANDLE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorControl, PSID, SE_DACL_PROTECTED,
        Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT},
    },
    Storage::FileSystem::FILE_ALL_ACCESS,
};

pub fn owner_credentials() -> Result<OwnerCredentials> {
    let sid = std::env::args().nth(3).context("fixture owner SID required")?;
    let root = PathBuf::from(std::env::args_os().nth(4).context("fixture owner directory required")?);
    let root = root.canonicalize()?;
    let bytes = std::fs::read(root.join(OWNER_TOKEN_FILE_NAME))?;
    ensure!(bytes.len() == 32, "invalid fixture owner token length");
    Ok(OwnerCredentials {
        identity: OwnerIdentity::Windows { sid },
        app_data_dir: root.to_string_lossy().into_owned(),
        token: Some(bytes.iter().map(|byte| format!("{byte:02x}")).collect()),
    })
}

struct LocalMemory(*mut c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn sid_string(sid: PSID) -> Result<String> {
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(std::io::Error::last_os_error()).context("format pipe ACE SID");
    }
    let _text = LocalMemory(text.cast());
    let length = (0..).take_while(|index| unsafe { *text.add(*index) != 0 }).count();
    Ok(String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })?)
}

fn verify_pipe_acl(pipe: HANDLE, owner: &str) -> Result<()> {
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(),
            &mut dacl, null_mut(), &mut descriptor,
        )
    };
    let _descriptor = LocalMemory(descriptor);
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32)).context("read live core pipe DACL");
    }
    ensure!(!descriptor.is_null() && !dacl.is_null(), "core pipe has no DACL");
    let mut flags = 0;
    let mut revision = 0;
    let read = unsafe { GetSecurityDescriptorControl(descriptor, &mut flags, &mut revision) };
    ensure!(read != 0 && flags & SE_DACL_PROTECTED != 0, "core pipe DACL is not protected");
    ensure!(unsafe { (*dacl).AceCount } == 3, "core pipe DACL must contain exactly three ACEs");

    let mut principals = Vec::new();
    for index in 0..3 {
        let mut ace = null_mut();
        let read = unsafe { GetAce(dacl, index, &mut ace) };
        ensure!(read != 0 && !ace.is_null(), "cannot read core pipe ACE");
        let header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
        ensure!(header.AceType == 0 && header.AceFlags == 0, "unexpected core pipe ACE type or flags");
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        ensure!(matches!(allowed.Mask, GENERIC_ALL | FILE_ALL_ACCESS), "unexpected core pipe ACE access mask");
        principals.push(sid_string(std::ptr::addr_of!(allowed.SidStart).cast_mut().cast())?);
    }
    principals.sort_unstable();
    let mut expected = [owner, "S-1-5-18", "S-1-5-32-544"];
    expected.sort_unstable();
    ensure!(principals.iter().map(String::as_str).eq(expected), "core pipe grants access to unexpected principals");
    Ok(())
}

pub async fn verify_generation(credentials: &OwnerCredentials, generation: Generation, installed_core: &Path) -> Result<()> {
    let _process = open_fixture(generation.pid, installed_core, 0)?;
    let OwnerIdentity::Windows { sid } = &credentials.identity else {
        anyhow::bail!("Windows owner required");
    };
    let pipe = service_pipe::open_verified(&mihomo_ipc_path(&credentials.identity), generation, Duration::from_secs(8)).await?;
    verify_pipe_acl(pipe.as_raw_handle(), sid)?;
    println!("PASS: installed core generation {} owns a protected pipe limited to the owner, SYSTEM, and Administrators", generation.pid);
    Ok(())
}
