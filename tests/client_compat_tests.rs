#![expect(
    clippy::panic,
    reason = "test harness code should panic on orchestration failures"
)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

struct ManagedChild {
    label: &'static str,
    child: Child,
}

impl ManagedChild {
    fn new(label: &'static str, child: Child) -> Self {
        Self { label, child }
    }

    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child
            .try_wait()
            .unwrap_or_else(|error| panic!("failed to inspect {} process: {error}", self.label))
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn allocate_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("failed to allocate local port: {error}"))
        .local_addr()
        .unwrap_or_else(|error| panic!("failed to read allocated port: {error}"))
        .port()
}

async fn wait_for_health(port: u16, child: &mut ManagedChild, timeout: Duration) {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|error| panic!("failed to build reqwest client: {error}"));

    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait() {
            panic!("{} exited before becoming healthy: {}", child.label, status);
        }

        if client
            .get(format!("http://127.0.0.1:{port}/__health"))
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    panic!(
        "{} server did not become healthy on port {} within {:?}",
        child.label, port, timeout
    );
}

fn start_reference_server(port: u16) -> ManagedChild {
    let child = Command::new("bun")
        .args(["run", "server.ts"])
        .current_dir(project_root().join("compat-tests/reference-server"))
        .env("PORT", port.to_string())
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start Bun reference server: {error}"));

    ManagedChild::new("ts-reference", child)
}

fn build_rust_compat_server() -> PathBuf {
    let output = Command::new("cargo")
        .args([
            "build",
            "--locked",
            "--manifest-path",
            "compat-tests/rust-server/Cargo.toml",
            "--message-format=json-render-diagnostics",
        ])
        .current_dir(project_root())
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|error| panic!("failed to build Rust compat server: {error}"));
    assert!(output.status.success(), "Rust compat server build failed");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find_map(|message| {
            let target = message.get("target")?.get("name")?.as_str()?;
            (target == "compat-rust-server")
                .then(|| message.get("executable")?.as_str().map(PathBuf::from))
                .flatten()
        })
        .unwrap_or_else(|| panic!("cargo did not report the compatibility server executable"))
}

fn start_rust_compat_server(port: u16, executable: &std::path::Path) -> ManagedChild {
    // Own the server process directly, so Drop cannot leave a cargo child behind.
    let child = Command::new(executable)
        .current_dir(project_root())
        .env("PORT", port.to_string())
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start Rust compat server: {error}"));
    ManagedChild::new("rust-compat", child)
}

fn run_bun_suite(paths: &[&str], ts_port: u16, rust_port: u16) {
    if paths == ["tests"] {
        let directory = project_root().join("compat-tests/client-tests/artifacts/evidence");
        if directory.exists() {
            std::fs::remove_dir_all(directory)
                .unwrap_or_else(|error| panic!("failed to reset capability evidence: {error}"));
        }
    }
    let output = Command::new("bun")
        .arg("test")
        .args(paths)
        .env(
            "COMPAT_COVERAGE",
            if paths == ["tests"] { "1" } else { "0" },
        )
        .current_dir(project_root().join("compat-tests/client-tests"))
        .env("AUTH_BASE_URL_TS", format!("http://localhost:{ts_port}"))
        .env(
            "AUTH_BASE_URL_RUST",
            format!("http://localhost:{rust_port}"),
        )
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .output()
        .unwrap_or_else(|error| panic!("failed to run Bun compatibility suite: {error}"));

    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Bun compatibility suite failed.\nstdout:\n{stdout}\n\nstderr:\n{stderr}");
    }
    if paths == ["tests"] {
        let status = Command::new("bun")
            .args(["run", "support/check-coverage.ts"])
            .current_dir(project_root().join("compat-tests/client-tests"))
            .status()
            .unwrap_or_else(|error| panic!("failed to check capability evidence: {error}"));
        assert!(status.success(), "capability evidence check failed");
    }
}

async fn run_client_compat(paths: &[&str]) {
    let executable = build_rust_compat_server();
    let ts_port = allocate_port();
    let rust_port = allocate_port();

    let mut ts_server = start_reference_server(ts_port);
    let mut rust_server = start_rust_compat_server(rust_port, &executable);

    wait_for_health(ts_port, &mut ts_server, Duration::from_secs(20)).await;
    wait_for_health(rust_port, &mut rust_server, Duration::from_secs(90)).await;

    run_bun_suite(paths, ts_port, rust_port);
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn account_management_client_compat() {
    run_client_compat(&["tests/account-management"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn admin_client_compat() {
    run_client_compat(&["tests/admin"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn api_key_client_compat() {
    run_client_compat(&["tests/api-key"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn core_client_compat() {
    run_client_compat(&["tests/core"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn device_authorization_client_compat() {
    run_client_compat(&["tests/device-authorization"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn email_verification_client_compat() {
    run_client_compat(&["tests/email-verification"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn generic_oauth_client_compat() {
    run_client_compat(&["tests/generic-oauth"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn oauth_client_compat() {
    run_client_compat(&["tests/oauth"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn organization_client_compat() {
    run_client_compat(&["tests/organization"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn passkey_client_compat() {
    run_client_compat(&["tests/passkey"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn password_management_client_compat() {
    run_client_compat(&["tests/password-management"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn sessions_client_compat() {
    run_client_compat(&["tests/sessions"]).await;
}

#[tokio::test]
#[ignore = "requires the pinned Bun and Rust compatibility servers"]
async fn siwe_client_compat() {
    run_client_compat(&["tests/siwe"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn two_factor_trust_client_compat() {
    run_client_compat(&["tests/two-factor/trust-ttl.test.ts"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn two_factor_client_compat() {
    run_client_compat(&["tests/two-factor"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn user_management_client_compat() {
    run_client_compat(&["tests/user-management"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn full_client_compat() {
    run_client_compat(&["tests"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers and Chromium"]
async fn browser_client_compat() {
    run_client_compat(&["browser"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn one_time_token_client_compat() {
    run_client_compat(&["tests/one-time-token"]).await;
}

#[tokio::test]
#[ignore = "requires local TypeScript/Rust fixture servers"]
async fn jwt_client_compat() {
    run_client_compat(&["tests/jwt"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn organization_teams_client_compat() {
    run_client_compat(&["tests/organization-extensions/teams.test.ts"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn organization_dynamic_roles_client_compat() {
    run_client_compat(&["tests/organization-extensions/dynamic-roles.test.ts"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn json_numbers_client_compat() {
    run_client_compat(&["tests/core/json-numbers.test.ts"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn phone_number_client_compat() {
    run_client_compat(&["tests/phone-number"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn username_availability_client_compat() {
    run_client_compat(&["tests/username"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn multiple_sessions_client_compat() {
    run_client_compat(&["tests/multiple-sessions"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn two_factor_totp_client_compat() {
    run_client_compat(&["tests/two-factor/totp-config.test.ts"]).await;
}

#[tokio::test]
#[ignore = "requires Bun and the compatibility fixtures"]
async fn two_factor_lockout_client_compat() {
    run_client_compat(&["tests/two-factor/lockout.test.ts"]).await;
}

#[tokio::test]
#[ignore = "requires the pinned Bun and Rust compatibility servers"]
async fn two_factor_skip_order_client_compat() {
    run_client_compat(&["tests/two-factor/skip-order.test.ts"]).await;
}

#[tokio::test]
#[ignore = "requires the pinned Bun and Rust compatibility servers"]
async fn two_factor_pending_cancel_client_compat() {
    run_client_compat(&["tests/two-factor/pending-cancel.test.ts"]).await;
}

#[tokio::test]
#[ignore = "requires the pinned Bun and Rust compatibility servers"]
async fn two_factor_passwordless_client_compat() {
    run_client_compat(&["tests/two-factor/passwordless.test.ts"]).await;
}

#[tokio::test]
#[ignore = "requires the pinned Bun and Rust compatibility servers"]
async fn two_factor_otp_config_client_compat() {
    run_client_compat(&["tests/two-factor/otp-config.test.ts"]).await;
}

#[tokio::test]
#[ignore = "starts external TS and Rust servers"]
async fn organization_hooks_client_compat() {
    run_client_compat(&[
        "tests/organization-extensions/creation-hooks.test.ts",
        "tests/organization-extensions/deletion-hooks.test.ts",
    ])
    .await;
}
