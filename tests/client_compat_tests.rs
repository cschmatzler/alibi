#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

struct ManagedChild {
    label: &'static str,
    child: Child,
}

impl ManagedChild {
    const fn new(label: &'static str, child: Child) -> Self {
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
        if matches!(self.child.try_wait(), Ok(None)) {
            // A normal fixture exit flushes LLVM counters from actual HTTP
            // execution. Keep cleanup bounded, including failed SDK runs.
            #[cfg(unix)]
            if Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .is_ok_and(|status| status.success())
            {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while matches!(self.child.try_wait(), Ok(None))
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
            if matches!(self.child.try_wait(), Ok(None)) {
                drop(self.child.kill());
            }
        }
        drop(self.child.wait());
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
            .is_ok_and(|response| response.status().is_success())
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

fn start_reference_server(port: u16, node_env: &str, test_flag: &str) -> ManagedChild {
    let child = Command::new("bun")
        .args(["run", "server.ts"])
        .current_dir(project_root().join("tests/compat/reference-server"))
        .env("PORT", port.to_string())
        .env("NODE_ENV", node_env)
        .env("BUN_ENV", node_env)
        .env("TEST", test_flag)
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| panic!("failed to start Bun reference server: {error}"));

    ManagedChild::new("ts-reference", child)
}

fn build_rust_compat_server() -> PathBuf {
    let mut command = Command::new("cargo");
    if let Some(target_dir) = std::env::var_os("BETTER_AUTH_COMPAT_COVERAGE_TARGET_DIR") {
        let _ = command.env("CARGO_TARGET_DIR", target_dir);
        // The LLVM wrapper instruments this workspace's dependencies, but the
        // standalone fixture also needs its own profiler runtime at link time.
        let _ = command.arg("rustc");
    } else {
        let _ = command.arg("build");
    }
    let _ = command.args([
        "--locked",
        "--manifest-path",
        "tests/compat/rust-server/Cargo.toml",
        "--message-format=json-render-diagnostics",
    ]);
    if std::env::var_os("BETTER_AUTH_COMPAT_COVERAGE_TARGET_DIR").is_some() {
        let _ = command.args(["--", "-C", "instrument-coverage"]);
    }
    let output = command
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

fn start_rust_compat_server(
    port: u16,
    executable: &std::path::Path,
    node_env: &str,
    test_flag: &str,
) -> ManagedChild {
    // Own the server process directly, so Drop cannot leave a cargo child behind.
    let child = Command::new(executable)
        .current_dir(project_root())
        .env("PORT", port.to_string())
        .env("NODE_ENV", node_env)
        .env("BUN_ENV", node_env)
        .env("TEST", test_flag)
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
        let directory = project_root().join("tests/compat/client-tests/artifacts/evidence");
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
        .current_dir(project_root().join("tests/compat/client-tests"))
        .env("AUTH_BASE_URL_TS", format!("http://localhost:{ts_port}"))
        .env(
            "AUTH_BASE_URL_RUST",
            format!("http://localhost:{rust_port}"),
        )
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("no_proxy", "localhost,127.0.0.1")
        .output()
        .unwrap_or_else(|error| panic!("failed to run Bun compatibility suite: {error}"));

    drop(write!(
        std::io::stdout().lock(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    ));
    drop(write!(
        std::io::stderr().lock(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    ));
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Bun compatibility suite failed.\nstdout:\n{stdout}\n\nstderr:\n{stderr}");
    }
    if paths == ["tests"] {
        let status = Command::new("bun")
            .args(["run", "support/check-coverage.ts"])
            .current_dir(project_root().join("tests/compat/client-tests"))
            .status()
            .unwrap_or_else(|error| panic!("failed to check capability evidence: {error}"));
        assert!(status.success(), "capability evidence check failed");
    }
}

async fn run_client_compat(paths: &[&str]) {
    let executable = build_rust_compat_server();
    if paths != ["environment"] {
        run_client_compat_in_environment(paths, &executable, "production", "false").await;
    }
    if paths == ["tests"] || paths == ["environment"] {
        // The published runtime caches NODE_ENV on import. Each mode needs
        // fresh fixture processes; mutating this test process cannot prove it.
        for (node_env, test_flag) in [
            ("dev", "false"),
            ("development", "false"),
            ("test", "false"),
            ("production", "0"),
        ] {
            run_client_compat_in_environment(&["environment"], &executable, node_env, test_flag)
                .await;
        }
    }
}

async fn run_client_compat_in_environment(
    paths: &[&str],
    executable: &std::path::Path,
    node_env: &str,
    test_flag: &str,
) {
    drop(writeln!(
        std::io::stderr().lock(),
        "Compatibility {paths:?}: NODE_ENV={node_env}, TEST={test_flag}"
    ));
    let ts_port = allocate_port();
    let rust_port = allocate_port();

    let mut ts_server = start_reference_server(ts_port, node_env, test_flag);
    let mut rust_server = start_rust_compat_server(rust_port, executable, node_env, test_flag);

    wait_for_health(ts_port, &mut ts_server, Duration::from_secs(20)).await;
    wait_for_health(rust_port, &mut rust_server, Duration::from_secs(90)).await;

    run_bun_suite(paths, ts_port, rust_port);
}

#[cfg(test)]
mod tests {
    use super::*;

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
    #[ignore = "starts fresh TS and Rust servers for each process environment"]
    async fn environment_client_compat() {
        run_client_compat(&["environment"]).await;
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
    async fn server_endpoints_client_compat() {
        run_client_compat(&["tests/server-endpoints"]).await;
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
    async fn two_factor_trust_client_compat() {
        run_client_compat(&["tests/two-factor/trust-ttl.test.ts"]).await;
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

    #[tokio::test]
    #[ignore = "requires the pinned Bun and Rust compatibility servers"]
    async fn captcha_client_compat() {
        run_client_compat(&["tests/captcha"]).await;
    }
}
