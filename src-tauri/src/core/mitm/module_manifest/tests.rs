use super::*;

#[test]
fn response_body_supports_optional_boolean_whole_match() -> Result<()> {
    let manifest = r#"
kind: netverge-module
schema: 1
id: com.example.whole-body
name: Whole response replacement
version: "1"
rewrite:
  - id: body
    type: response-body
    match:
      host: api.example.test
      path: /v1
    action:
      search: "original"
      replace: "new"
      match-whole: true
"#;
    let out = parse_and_compile_manifest("module.yaml", manifest)
        .map_err(|diag| anyhow::anyhow!(diag.message))?;
    assert_eq!(out.rewrites.body[0].match_whole, Some(true));
    let legacy = manifest.replace("      match-whole: true\n", "");
    let out = parse_and_compile_manifest("module.yaml", &legacy)
        .map_err(|diag| anyhow::anyhow!(diag.message))?;
    assert_eq!(out.rewrites.body[0].match_whole, None);
    let invalid = manifest.replace("match-whole: true", "match-whole: 'true'");
    assert!(parse_and_compile_manifest("module.yaml", &invalid).is_err());
    Ok(())
}

#[test]
fn url_query_removal_compiles_and_checks_names() -> Result<()> {
    let manifest = r#"
kind: netverge-module
schema: 1
id: com.example.query
name: Query removal
version: "1"
rewrite:
  - id: drop-debug
    type: url
    match:
      host: api.example.test
      path: /v1
    action:
      remove-query: [debug, trace.id]
"#;
    let out = parse_and_compile_manifest("module.yaml", manifest)
        .map_err(|diag| anyhow::anyhow!(diag.message))?;
    let rule = &out.rewrites.path[0];
    assert_eq!(
        rule.remove_query.as_deref(),
        Some(["debug".to_owned(), "trace.id".to_owned()].as_slice())
    );
    assert!(rule.target.is_empty());

    for names in ["[]", "[debug, debug]", "['raw=name']", "['debug%20']"] {
        let invalid = manifest.replace("[debug, trace.id]", names);
        assert!(parse_and_compile_manifest("module.yaml", &invalid).is_err(), "{names}");
    }
    let ambiguous = manifest.replace("      remove-query:", "      replace: /v2\n      remove-query:");
    assert!(parse_and_compile_manifest("module.yaml", &ambiguous).is_err());
    Ok(())
}

#[test]
fn header_removal_compiles_and_checks_names() -> Result<()> {
    let manifest = r#"
kind: netverge-module
schema: 1
id: com.example.remove
name: Remove diagnostic header
version: "1"
rewrite:
  - id: drop-debug
    type: request-header
    match:
      host: api.example.test
      path: /v1
    action:
      remove: [X-Custom-Debug]
"#;
    let out = parse_and_compile_manifest("module.yaml", manifest)
        .map_err(|diag| anyhow::anyhow!(diag.message))?;
    let rule = &out.rewrites.request[0];
    assert_eq!(rule.remove, Some(true));
    assert_eq!(rule.header, "X-Custom-Debug");
    assert!(rule.value.is_empty());

    for headers in ["[]", "[Host]", "[X-Custom-Debug, x-custom-debug]"] {
        let invalid = manifest.replace("[X-Custom-Debug]", headers);
        assert!(parse_and_compile_manifest("module.yaml", &invalid).is_err(), "{headers}");
    }
    let ambiguous = manifest.replace("      remove:", "      set: {X-Custom-Debug: '1'}\n      remove:");
    assert!(parse_and_compile_manifest("module.yaml", &ambiguous).is_err());
    Ok(())
}

#[test]
fn mock_and_map_local_compile_and_reject_unsafe_actions() -> Result<()> {
    let manifest = r#"
kind: netverge-module
schema: 1
id: com.example.mock
name: Local responses
version: "1.0"
rewrite:
  - id: inline-json
    type: mock
    match:
      host: api.example.test
      path: /v1/mock
    action:
      status: 201
      content-type: application/json; charset=utf-8
      headers:
        X-Mock: inline
      body: '{"ok":true}'
  - id: empty-no-content
    type: mock
    match:
      host: api.example.test
      path: /v1/empty
      method: DELETE
    action:
      status: 204
  - id: mapped-asset
    type: map-local
    match:
      host: api.example.test
      path: /v1/asset
    action:
      file: assets/mock.json
      headers:
        X-Source: asset
"#;
    let out = parse_and_compile_manifest("module.yaml", manifest)
        .map_err(|diag| anyhow::anyhow!(diag.message))?;
    assert_eq!(out.rewrites.local.len(), 3);
    assert_eq!(out.rewrites.local[0].status, 201);
    assert_eq!(out.rewrites.local[0].body_len, 11);
    assert_eq!(out.inline_blobs.get(&out.rewrites.local[0].body_sha256).map(Vec::as_slice), Some(b"{\"ok\":true}".as_slice()));
    assert_eq!(out.rewrites.local[1].status, 204);
    assert_eq!(out.rewrites.local[1].content_type, None);
    assert_eq!(out.rewrites.local[1].body_len, 0);
    assert_eq!(out.rewrites.local[2].content_type.as_deref(), Some("application/json; charset=utf-8"));
    assert_eq!(out.map_local_files, vec![(2, "assets/mock.json".to_owned())]);

    for bad in [
        "status: 302\n      body: redirect",
        "status: 407\n      body: auth",
        "status: '200'\n      body: str-status",
        "status: 204\n      body: non-empty",
        "status: 204\n      content-type: text/plain",
        "content-type: bad\n      body: x",
        "headers: { Set-Cookie: a=1 }\n      body: x",
        "headers: {}\n      body: x",
        "file: assets/mock.json\n      body: x",
    ] {
        let candidate = format!(
            "kind: netverge-module\nschema: 1\nid: com.example.bad\nname: Bad\nversion: '1'\nrewrite:\n  - id: m\n    type: mock\n    match: {{ host: api.example.test, path: /v1 }}\n    action:\n      {bad}\n"
        );
        assert!(parse_and_compile_manifest("module.yaml", &candidate).is_err(), "{bad}");
    }
    for bad_map in [
        "status: 204\n      file: assets/mock.json",
        "status: 200",
        "file: ''",
        "file: assets/mock.json\n      body: extra",
    ] {
        let candidate = format!(
            "kind: netverge-module\nschema: 1\nid: com.example.bad\nname: Bad\nversion: '1'\nrewrite:\n  - id: m\n    type: map-local\n    match: {{ host: api.example.test, path: /v1 }}\n    action:\n      {bad_map}\n"
        );
        assert!(parse_and_compile_manifest("module.yaml", &candidate).is_err(), "{bad_map}");
    }
    Ok(())
}

#[test]
fn parses_native_manifest_and_rejects_unsafe_yaml_constructs() -> Result<()> {
    let valid = r#"
kind: netverge-module
schema: 1
id: com.example.api-debug
name: API debug
version: "1.0.0"
mitm:
  hostnames:
    - api.example.test
rewrite:
  - id: redirect-v1
    type: url
    match:
      host: api.example.test
      path: /v1
    action:
      replace: /v2
  - id: add-debug
    type: request-header
    match:
      host: api.example.test
    action:
      set:
        X-Custom-Debug: "true"
scripts:
  - id: inspect-res
    type: http-response
    match:
      host: api.example.test
    script: modules/api-debug/debug.js
    requires-body: true
    timeout: 5
"#;
    let out = parse_and_compile_manifest("modules/api-debug/module.yaml", valid)
        .map_err(|diag| anyhow::anyhow!(diag.message))?;
    assert_eq!(out.manifest.id, "com.example.api-debug");
    assert_eq!(out.rewrites.path[0].id.as_deref(), Some("com.example.api-debug:redirect-v1"));
    assert_eq!(out.rewrites.request[0].source.as_deref(), Some("module:com.example.api-debug"));
    assert_eq!(out.rewrites.request[0].path, "");
    assert_eq!(out.rewrites.request[0].regex.as_deref(), Some(r"^https://api\.example\.test/"));

    for bad in [
        "kind: netverge-module\nschema: 2\nid: com.example.a\nname: A\nversion: '1'\n",
        "kind: netverge-module\nschema: 1\nid: com.example.a\nname: &a A\nauthor: *a\nversion: '1'\n",
        "kind: netverge-module\nschema: 1\nid: com.example.a\nname: !custom A\nversion: '1'\n",
        "kind: netverge-module\nschema: 1\nid: com.example.a\nname: A\nversion: '1'\n<<: {}\n",
        "kind: netverge-module\nschema: 1\nid: com.example.a\nname: A\nname: B\nversion: '1'\n",
        "kind: netverge-module\nschema: 1\nid: com.example.a\nname: A\nversion: '1'\nextra: 1\n",
        "kind: netverge-module\nschema: 1\nid: com.example.a\nname: A\nversion: '1'\n---\nkind: netverge-module\n",
    ] {
        let Err(diag) = parse_and_compile_manifest("module.yaml", bad) else {
            bail!("expected rejection for malformed manifest");
        };
        assert!(!diag.message.is_empty());
    }
    Ok(())
}
