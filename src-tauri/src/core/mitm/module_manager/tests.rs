use super::*;

#[test]
fn discovers_validates_approves_preserves_on_edit_and_switches_profiles() -> Result<()> {
    let rev = SNAPSHOT_REVISION.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("nv-mod-mgr-{}-{rev}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let result = (|| -> Result<()> {
        let mitm_dir = root.join("mitm");
        let ws_a = root.join("profiles/prof-a");
        let ws_b = root.join("profiles/prof-b");
        std::fs::create_dir_all(ws_a.join("modules/debug"))?;
        std::fs::create_dir_all(ws_a.join("scripts"))?;
        std::fs::create_dir_all(ws_a.join("assets"))?;
        std::fs::create_dir_all(&ws_b)?;
        std::fs::write(ws_a.join("scripts/hook.js"), b"$done({});\n")?;
        std::fs::write(ws_a.join("assets/mock.json"), br#"{"version":1}"#)?;
        std::fs::write(
            ws_a.join("module.yaml"),
            "kind: netverge-module\nschema: 1\nid: com.example.escape\nname: Escape\nversion: '1.0'\nrewrite:\n  - id: bad\n    type: map-local\n    match:\n      host: api.example.test\n      path: /escape\n    action:\n      file: ../outside.json\n",
        )?;
        std::fs::write(
            ws_a.join("modules/debug/module.yaml"),
            "kind: netverge-module\nschema: 1\nid: com.example.debug\nname: Debug\nversion: '1.0'\nmitm:\n  hostnames:\n    - extra.example.test\nrewrite:\n  - id: h1\n    type: response-header\n    match:\n      host: api.example.test\n      path: /demo\n    action:\n      set:\n        X-Module: v1\n  - id: m1\n    type: map-local\n    match:\n      host: api.example.test\n      path: /mock\n    action:\n      file: assets/mock.json\nscripts:\n  - id: s1\n    type: http-response\n    match:\n      host: api.example.test\n    script: scripts/hook.js\n",
        )?;

        let preview = preview_modules_in_dirs(&mitm_dir, Some("prof-a"), Some(&ws_a), &[])?;
        assert_eq!(preview.diagnostics.len(), 1);
        assert_eq!(preview.modules.len(), 1);
        assert_eq!(preview.modules[0].id, "com.example.debug");
        assert_eq!(preview.modules[0].rewrite_count, 2);
        assert_eq!(preview.modules[0].state, ModuleApprovalState::Unapproved);
        assert_eq!(preview.modules[0].missing_mitm_hostnames, vec!["extra.example.test"]);
        assert!(!mitm_dir.join(COMPILED_MODULE_FILE).exists());

        assert!(set_module_approval_in_dirs(&mitm_dir, "prof-a", &ws_a, "com.example.debug", "stale", true, &[]).is_err());
        let sha = preview.modules[0].content_sha256.clone();
        let active = set_module_approval_in_dirs(&mitm_dir, "prof-a", &ws_a, "com.example.debug", &sha, true, &[])?;
        assert_eq!(active.modules[0].state, ModuleApprovalState::Active);
        let blob_v1 = sha256_hex(br#"{"version":1}"#);
        assert_eq!(std::fs::read(mitm_dir.join(APPROVED_BLOBS_DIR).join(&blob_v1))?, br#"{"version":1}"#);

        // Editing the referenced map-local asset marks UpdatePending while retaining approved v1 bytes.
        std::fs::write(ws_a.join("assets/mock.json"), br#"{"version":2}"#)?;
        let edited = preview_modules_in_dirs(&mitm_dir, Some("prof-a"), Some(&ws_a), &[])?;
        assert_eq!(edited.modules[0].state, ModuleApprovalState::UpdatePending);
        write_compiled_snapshot_in_dirs(&mitm_dir, Some("prof-b"), Some(&ws_b))?;
        assert!(!mitm_dir.join(COMPILED_MODULE_FILE).exists());
        write_compiled_snapshot_in_dirs(&mitm_dir, Some("prof-a"), Some(&ws_a))?;
        let compiled_bytes = std::fs::read_to_string(mitm_dir.join(COMPILED_MODULE_FILE))?;
        assert!(compiled_bytes.contains(&blob_v1));
        assert_eq!(std::fs::read(mitm_dir.join(APPROVED_BLOBS_DIR).join(&blob_v1))?, br#"{"version":1}"#);

        // Re-approving commits v2 and prunes the unreferenced v1 blob.
        let sha_v2 = edited.modules[0].content_sha256.clone();
        let reapproved = set_module_approval_in_dirs(&mitm_dir, "prof-a", &ws_a, "com.example.debug", &sha_v2, true, &[])?;
        assert_eq!(reapproved.modules[0].state, ModuleApprovalState::Active);
        let blob_v2 = sha256_hex(br#"{"version":2}"#);
        assert!(!mitm_dir.join(APPROVED_BLOBS_DIR).join(&blob_v1).exists());
        assert_eq!(std::fs::read(mitm_dir.join(APPROVED_BLOBS_DIR).join(&blob_v2))?, br#"{"version":2}"#);
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&root);
    result
}

#[test]
fn script_assets_are_pinned_and_legacy_approvals_require_review() -> Result<()> {
    let rev = SNAPSHOT_REVISION.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("nv-script-approval-{}-{rev}", std::process::id()));
    let result = (|| -> Result<()> {
        let mitm = root.join("mitm");
        let ws = root.join("profiles/prof-a");
        std::fs::create_dir_all(ws.join("scripts"))?;
        let source = ws.join("scripts/hook.js");
        let original = b"$done({});";
        let changed = b"$done({body: 'new'});";
        std::fs::write(&source, original)?;
        std::fs::write(ws.join("module.yaml"), r#"
kind: netverge-module
schema: 1
id: com.example.scripts
name: Scripts
version: '1'
scripts:
  - id: response
    type: http-response
    match:
      host: api.example.test
      path: /demo
      method: GET
    script: scripts/hook.js
    requires-body: true
    max-size: 4096
    timeout: 2
    argument: example
"#)?;
        let preview = || preview_modules_in_dirs(&mitm, Some("prof-a"), Some(&ws), &[]);
        let approve = |sha: &str, enabled| set_module_approval_in_dirs(
            &mitm, "prof-a", &ws, "com.example.scripts", sha, enabled, &[]);
        let first = preview()?.modules.remove(0);
        assert_eq!(first.state, ModuleApprovalState::Unapproved);
        let digest = sha256_hex(original);
        let blob_path = mitm.join(APPROVED_BLOBS_DIR).join(&digest);
        assert!(!blob_path.exists());
        approve(&first.content_sha256, true)?;
        let stored = read_approval_store(&mitm, "prof-a")?;
        let pins = &stored.modules["com.example.scripts"].approved_scripts;
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].source_sha256, digest);
        assert_eq!(pins[0].source_len as usize, original.len());
        assert_eq!(pins[0].entry.timeout, Some(2));
        assert_eq!(pins[0].entry.condition.method.as_deref(), Some("GET"));
        assert_eq!(std::fs::read(&blob_path)?, original);
        // No script instructions reach the current production rewrite worker.
        assert!(!mitm.join(COMPILED_MODULE_FILE).exists());

        // Simulate a store created before script pinning was implemented.
        let store_path = approval_file(&mitm, "prof-a")?;
        let mut legacy = stored;
        legacy.modules.get_mut("com.example.scripts").context("missing module")?.approved_scripts.clear();
        std::fs::write(&store_path, serde_json::to_vec(&legacy)?)?;
        assert_eq!(preview()?.modules[0].state, ModuleApprovalState::UpdatePending);
        approve(&first.content_sha256, true)?;
        assert_eq!(preview()?.modules[0].state, ModuleApprovalState::Active);

        std::fs::write(&source, changed)?;
        let pending = preview()?.modules.remove(0);
        assert_eq!(pending.state, ModuleApprovalState::UpdatePending);
        assert_ne!(pending.content_sha256, first.content_sha256);
        assert!(approve(&first.content_sha256, true).is_err());
        assert_eq!(std::fs::read(&blob_path)?, original);
        let disabled = approve(&pending.content_sha256, false)?;
        assert!(!disabled.modules[0].enabled);
        let store = read_approval_store(&mitm, "prof-a")?;
        assert_eq!(store.modules["com.example.scripts"].approved_sha256, first.content_sha256);
        assert_eq!(store.modules["com.example.scripts"].approved_scripts[0].source_sha256, digest);
        assert_eq!(std::fs::read(&blob_path)?, original);

        approve(&pending.content_sha256, true)?;
        assert!(!blob_path.exists());
        let next_blob = mitm.join(APPROVED_BLOBS_DIR).join(sha256_hex(changed));
        assert_eq!(std::fs::read(&next_blob)?, changed);
        assert!(!mitm.join(COMPILED_MODULE_FILE).exists());

        std::fs::write(&source, vec![b'x'; 65_537])?;
        let invalid = preview()?;
        assert!(invalid.modules.is_empty());
        assert_eq!(invalid.diagnostics.len(), 1);
        assert!(invalid.diagnostics[0].message.contains("65536"));
        assert_eq!(std::fs::read(next_blob)?, changed);
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&root);
    result
}
