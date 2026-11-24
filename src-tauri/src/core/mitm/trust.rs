//! Read-only native trust assessment and explicit public CA export.
//! No certificate installation, private key access, arbitrary input or elevation.
use super::{MitmPublicCa, public_ca};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::{io::AsyncWriteExt as _, sync::Semaphore};

static INSPECTION: Semaphore = Semaphore::const_new(1);
static EXPORT: Semaphore = Semaphore::const_new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum MitmStoreMatch {
    #[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
    Present,
    #[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
    Absent,
    Unknown,
    // Keep the same serialized contract on all platforms.
    #[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum MitmTrustAssessment {
    NoCertificate,
    // Windows membership and macOS policy evaluation have different semantics.
    // Preserve all wire variants; only suppress platform-specific dead-code lint.
    #[cfg_attr(not(windows), allow(dead_code))]
    NotFoundInCheckedStores,
    #[cfg_attr(not(windows), allow(dead_code))]
    PresentUnverified,
    #[cfg_attr(not(windows), allow(dead_code))]
    ExplicitlyDistrusted,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    RootPolicyAccepted,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    RootPolicyRejected,
    Unknown,
    #[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
    Unsupported,
}

#[derive(Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct MitmTrustStatus {
    fingerprint: Option<String>,
    user_store: MitmStoreMatch,
    system_store: MitmStoreMatch,
    assessment: MitmTrustAssessment,
}

impl MitmTrustStatus {
    fn new(fingerprint: Option<String>, assessment: MitmTrustAssessment) -> Self {
        Self { fingerprint, user_store: MitmStoreMatch::Unknown, system_store: MitmStoreMatch::Unknown, assessment }
    }
}

fn ca_der(ca: &MitmPublicCa) -> Result<Vec<u8>> {
    let encoded = ca.pem.strip_prefix("-----BEGIN CERTIFICATE-----\n")
        .and_then(|pem| pem.strip_suffix("-----END CERTIFICATE-----\n"))
        .context("invalid MITM CA PEM")?;
    let der = STANDARD.decode(encoded.lines().collect::<String>())?;
    let fingerprint: String = Sha256::digest(&der).iter().map(|byte| format!("{byte:02x}")).collect();
    ensure!(fingerprint == ca.sha256_fingerprint, "MITM CA fingerprint mismatch");
    Ok(der)
}

#[cfg(any(windows, test))]
fn membership_assessment(user: MitmStoreMatch, system: MitmStoreMatch, denied: bool, deny_unknown: bool) -> MitmTrustAssessment {
    use MitmStoreMatch::{Absent, Present};
    if denied {
        MitmTrustAssessment::ExplicitlyDistrusted
    } else if deny_unknown {
        MitmTrustAssessment::Unknown
    } else if user == Present || system == Present {
        MitmTrustAssessment::PresentUnverified
    } else if user == Absent && system == Absent {
        MitmTrustAssessment::NotFoundInCheckedStores
    } else {
        MitmTrustAssessment::Unknown
    }
}

#[cfg(windows)]
fn windows_store_match(name: &str, location: u32, der: &[u8]) -> MitmStoreMatch {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CRYPT_E_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Security::Cryptography::{
        CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
        CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore,
    };
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: the UTF-16 name remains valid for the synchronous native call.
    let store = unsafe {
        CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
            location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
            name.as_ptr().cast())
    };
    if store.is_null() {
        return MitmStoreMatch::Unknown;
    }
    let mut previous = ptr::null();
    let result = loop {
        // SAFETY: enumeration releases the previous context, if any. The
        // current context and encoded DER remain valid until the next call.
        let current = unsafe { CertEnumCertificatesInStore(store, previous) };
        if current.is_null() {
            let error = unsafe { GetLastError() };
            break if error as i32 == CRYPT_E_NOT_FOUND {
                MitmStoreMatch::Absent
            } else {
                MitmStoreMatch::Unknown
            };
        }
        let matches = unsafe {
            let context = &*current;
            !context.pbCertEncoded.is_null()
                && context.cbCertEncoded as usize == der.len()
                && std::slice::from_raw_parts(context.pbCertEncoded, der.len()) == der
        };
        if matches {
            unsafe { CertFreeCertificateContext(current) };
            break MitmStoreMatch::Present;
        }
        previous = current;
    };
    // SAFETY: the handle was opened above, and the final context is released.
    unsafe { CertCloseStore(store, 0) };
    result
}

#[cfg(windows)]
fn inspect_native(der: &[u8], fingerprint: String) -> MitmTrustStatus {
    use windows_sys::Win32::Security::Cryptography::{
        CERT_SYSTEM_STORE_CURRENT_USER_ID, CERT_SYSTEM_STORE_LOCAL_MACHINE_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT,
    };
    use MitmStoreMatch::{Present, Unknown};
    let user = CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;
    let machine = CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;
    let user_store = windows_store_match("Root", user, der);
    let system_store = windows_store_match("Root", machine, der);
    let denied_user = windows_store_match("Disallowed", user, der);
    let denied_machine = windows_store_match("Disallowed", machine, der);
    let assessment = membership_assessment(user_store, system_store,
        denied_user == Present || denied_machine == Present,
        denied_user == Unknown || denied_machine == Unknown);
    // Logical CurrentUser Root may inherit LocalMachine roots. Membership
    // is not ownership and is not proof of successful TLS chain validation.
    MitmTrustStatus { fingerprint: Some(fingerprint), user_store, system_store, assessment }
}

#[cfg(target_os = "macos")]
fn inspect_native(der: &[u8], fingerprint: String) -> MitmTrustStatus {
    use security_framework::{certificate::SecCertificate, policy::SecPolicy, trust::SecTrust, trust_settings::{Domain, TrustSettings}};
    fn membership(der: &[u8], domain: Domain) -> MitmStoreMatch {
        match TrustSettings::new(domain).iter() {
            Ok(mut certs) => if certs.any(|cert| cert.to_der() == der) {
                MitmStoreMatch::Present
            } else {
                MitmStoreMatch::Absent
            },
            Err(_) => MitmStoreMatch::Unknown,
        }
    }
    // These are trust-settings domains, not arbitrary keychain file searches.
    let user_store = membership(der, Domain::User);
    let system_store = membership(der, Domain::Admin);
    let assessment = (|| -> Result<MitmTrustAssessment> {
        let cert = SecCertificate::from_der(der)?;
        let mut trust = SecTrust::create_with_certificates(&[cert], &[SecPolicy::create_x509()])?;
        trust.set_network_fetch_allowed(false)?;
        Ok(if trust.evaluate_with_error().is_ok() {
            MitmTrustAssessment::RootPolicyAccepted
        } else {
            MitmTrustAssessment::RootPolicyRejected
        })
    })().unwrap_or(MitmTrustAssessment::Unknown);
    // Basic X.509 policy on the root does not prove TLS for every leaf/hostname.
    MitmTrustStatus { fingerprint: Some(fingerprint), user_store, system_store, assessment }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn inspect_native(_der: &[u8], fingerprint: String) -> MitmTrustStatus {
    MitmTrustStatus {
        fingerprint: Some(fingerprint), user_store: MitmStoreMatch::Unsupported,
        system_store: MitmStoreMatch::Unsupported, assessment: MitmTrustAssessment::Unsupported,
    }
}

pub(crate) async fn inspect() -> MitmTrustStatus {
    let Some(ca) = public_ca() else {
        return MitmTrustStatus::new(None, MitmTrustAssessment::NoCertificate);
    };
    let fingerprint = ca.sha256_fingerprint.clone();
    let Ok(permit) = INSPECTION.try_acquire() else {
        return MitmTrustStatus::new(Some(fingerprint), MitmTrustAssessment::Unknown);
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        match ca_der(&ca) {
            Ok(der) => inspect_native(&der, ca.sha256_fingerprint),
            Err(_) => MitmTrustStatus::new(Some(ca.sha256_fingerprint), MitmTrustAssessment::Unknown),
        }
    });
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), result).await;
    let current = public_ca().map(|ca| ca.sha256_fingerprint);
    if current.as_deref() != Some(fingerprint.as_str()) {
        return MitmTrustStatus::new(current, MitmTrustAssessment::Unknown);
    }
    match result {
        Ok(Ok(status)) => status,
        _ => MitmTrustStatus::new(Some(fingerprint), MitmTrustAssessment::Unknown),
    }
}

async fn write_new_public_ca(path: &Path, ca: &MitmPublicCa) -> Result<()> {
    ca_der(ca)?;
    ensure!(path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("crt") || ext.eq_ignore_ascii_case("pem")), "choose a .crt or .pem certificate file");
    let mut file = tokio::fs::OpenOptions::new().write(true).create_new(true).open(path).await
        .context("cannot create certificate file; choose a new filename")?;
    file.write_all(ca.pem.as_bytes()).await?;
    file.sync_all().await?;
    Ok(())
}

pub(crate) async fn export() -> Result<bool> {
    let _permit = EXPORT.try_acquire().context("certificate export already running")?;
    let ca = public_ca().context("no verified MITM public certificate is available")?;
    let file = rfd::AsyncFileDialog::new()
        .set_title("Export NetVerge public CA")
        .add_filter("Public certificate", &["crt", "pem"])
        .set_file_name("NetVerge-CA.crt")
        .save_file().await;
    let Some(file) = file else { return Ok(false) };
    ensure!(public_ca().is_some_and(|current| current.sha256_fingerprint == ca.sha256_fingerprint),
        "MITM CA changed while exporting; retry");
    write_new_public_ca(file.path(), &ca).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_membership_is_not_ownership_or_full_tls_trust() {
        use MitmStoreMatch::{Absent, Present, Unknown};
        assert_eq!(membership_assessment(Present, Absent, false, false), MitmTrustAssessment::PresentUnverified);
        assert_eq!(membership_assessment(Present, Present, true, false), MitmTrustAssessment::ExplicitlyDistrusted);
        assert_eq!(membership_assessment(Present, Absent, false, true), MitmTrustAssessment::Unknown);
        assert_eq!(membership_assessment(Absent, Unknown, false, false), MitmTrustAssessment::Unknown);
        assert_eq!(membership_assessment(Absent, Absent, false, false), MitmTrustAssessment::NotFoundInCheckedStores);
    }

    // Public-only test fixture, generated for this test; its key was discarded.
    fn fixture() -> Result<MitmPublicCa> {
        super::super::public_ca_from_der(include_str!("test-ca.der.b64").trim())
    }

    #[tokio::test]
    async fn export_writes_only_verified_public_ca_and_never_overwrites() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("netverge-ca-export-{}", nanoid::nanoid!(12)));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("new.crt");
        let invalid = dir.join("invalid.crt");
        let wrong_extension = dir.join("new.txt");
        let ca = fixture()?;
        let result = async {
            write_new_public_ca(&path, &ca).await?;
            assert_eq!(std::fs::read_to_string(&path)?, ca.pem);
            assert!(write_new_public_ca(&path, &ca).await.is_err());
            assert_eq!(std::fs::read_to_string(&path)?, ca.pem);
            assert!(write_new_public_ca(&wrong_extension, &ca).await.is_err());
            assert!(!wrong_extension.exists());
            let tampered = MitmPublicCa { sha256_fingerprint: "invalid".into(), pem: ca.pem.clone() };
            assert!(write_new_public_ca(&invalid, &tampered).await.is_err());
            assert!(!invalid.exists());
            Ok::<(), anyhow::Error>(())
        }.await;
        let cleanup = std::fs::remove_dir_all(&dir);
        result?;
        cleanup?;
        Ok(())
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn isolated_test_ca_is_not_reported_as_trusted() -> Result<()> {
        let ca = fixture()?;
        let der = ca_der(&ca)?;
        let status = inspect_native(&der, ca.sha256_fingerprint.clone());
        assert_eq!(status.fingerprint.as_deref(), Some(ca.sha256_fingerprint.as_str()));
        assert_ne!(status.user_store, MitmStoreMatch::Present);
        assert_ne!(status.system_store, MitmStoreMatch::Present);
        assert_ne!(status.assessment, MitmTrustAssessment::RootPolicyAccepted);
        Ok(())
    }
}
