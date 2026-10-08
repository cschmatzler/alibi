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
    // Keep assignments unique until every child has bound. Dropping an ephemeral
    // listener before spawning previously let parallel workers reuse its port.
    static ASSIGNED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
        std::sync::OnceLock::new();
    let mut assigned = ASSIGNED
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
        .expect("port allocation lock");
    loop {
        // Avoid the standard ephemeral range used by outgoing health/SDK
        // connections while the child is starting and has not bound yet.
        let ports = match std::env::var("BETTER_AUTH_COMPAT_BACKEND").as_deref() {
            Ok("seaorm") => 20_000..30_000,
            _ => 10_000..20_000,
        };
        let port = rand::random_range(ports);
        if assigned.contains(&port) {
            continue;
        }
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => drop(listener),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("failed to allocate local port: {error}"),
        }
        if assigned.insert(port) {
            return port;
        }
    }
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

fn start_reference_server(
    port: u16,
    node_env: &str,
    test_flag: &str,
    proxy_environment: bool,
) -> ManagedChild {
    let child = Command::new("bun")
        .args(["run", "server.ts"])
        .current_dir(project_root().join("tests/compat/reference-server"))
        // The process owner deliberately distinguishes vendor receiver, configured
        // auth base, and production skip URL. Keep these inputs out of other suites.
        .envs(proxy_environment.then(|| [
            ("NETLIFY_URL", format!("http://localhost:{port}")),
            ("BETTER_AUTH_URL", format!("http://127.0.0.1:{port}")),
        ]).into_iter().flatten())
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
    if let Some(executable) = std::env::var_os("BETTER_AUTH_COMPAT_EXECUTABLE") {
        let executable = PathBuf::from(executable);
        assert!(
            executable.is_file(),
            "prebuilt compatibility server does not exist"
        );
        return executable;
    }
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
    // Fixtures use `SqlxStore`; `BETTER_AUTH_COMPAT_BACKEND=seaorm` serves
    // every fixture from `SeaOrmStore` instead.
    match std::env::var("BETTER_AUTH_COMPAT_BACKEND").as_deref() {
        Ok("seaorm") => {
            let _ = command.args(["--features", "seaorm"]);
        }
        Ok("sqlx") | Err(_) => {}
        Ok(other) => panic!("BETTER_AUTH_COMPAT_BACKEND must be seaorm or sqlx, not {other}"),
    }
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
    proxy_environment: bool,
    salesforce_proxy: Option<&str>,
) -> ManagedChild {
    // Own the server process directly, so Drop cannot leave a cargo child behind.
    let child = Command::new(executable)
        .current_dir(project_root())
        // The process owner deliberately distinguishes vendor receiver, configured
        // auth base, and production skip URL. Keep these inputs out of other suites.
        .envs(proxy_environment.then(|| [
            ("NETLIFY_URL", format!("http://localhost:{port}")),
            ("BETTER_AUTH_URL", format!("http://127.0.0.1:{port}")),
        ]).into_iter().flatten())
        .envs(salesforce_proxy.into_iter().flat_map(|proxy| [
            ("HTTPS_PROXY", proxy.to_owned()),
            ("https_proxy", proxy.to_owned()),
            ("SSL_CERT_FILE", project_root().join("tests/compat/fixtures/salesforce-transport/cert.pem").display().to_string()),
        ]))
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

fn reset_compat_evidence() {
    let namespace = std::env::var("COMPAT_ARTIFACT_NAMESPACE").unwrap_or_default();
    assert!(
        ["", "sqlx", "seaorm"].contains(&namespace.as_str()),
        "invalid compatibility artifact namespace"
    );
    for evidence in ["evidence", "oracle"] {
        let directory = project_root()
            .join("tests/compat/client-tests/artifacts")
            .join(&namespace)
            .join(evidence);
        if directory.exists() {
            std::fs::remove_dir_all(directory)
                .unwrap_or_else(|error| panic!("failed to reset {evidence} receipts: {error}"));
        }
    }
}

fn run_bun_suite(
    paths: &[&str],
    ts_port: u16,
    rust_port: u16,
    coverage: bool,
    ts_server: &mut ManagedChild,
    rust_server: &mut ManagedChild,
) {
    let started = std::time::Instant::now();
    let output = Command::new("bun")
        .arg("test")
        .args(paths)
        .env("COMPAT_COVERAGE", if coverage { "1" } else { "0" })
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
    drop(writeln!(
        std::io::stderr().lock(),
        "Compatibility file time [{}] {paths:?}: {:.3}s",
        std::env::var("BETTER_AUTH_COMPAT_BACKEND").unwrap_or_else(|_| "sqlx".into()),
        started.elapsed().as_secs_f64()
    ));
    if !output.status.success() {
        panic!(
            "Bun compatibility suite failed for {paths:?}; fixture exit states: TS={:?}, Rust={:?}; diagnostics printed above",
            ts_server.try_wait(),
            rust_server.try_wait()
        );
    }
}

fn check_compat_evidence(inventory_only: bool) {
    let mut command = Command::new("bun");
    _ = command.args(["run", "support/check-coverage.ts"]);
    if inventory_only {
        _ = command.arg("--inventory-only");
    }
    let status = command
        .current_dir(project_root().join("tests/compat/client-tests"))
        .status()
        .unwrap_or_else(|error| panic!("failed to check capability evidence: {error}"));
    assert!(status.success(), "capability evidence check failed");
}

fn scenario_files(paths: &[&str]) -> (usize, Vec<String>) {
    fn collect(path: &std::path::Path, files: &mut Vec<(u64, String)>) {
        if path.is_dir() {
            for entry in std::fs::read_dir(path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
            {
                collect(&entry.expect("scenario directory entry").path(), files);
            }
        } else if path.to_string_lossy().ends_with(".test.ts") {
            let root = project_root().join("tests/compat/client-tests");
            files.push((
                path.metadata().expect("scenario file metadata").len(),
                path.strip_prefix(root)
                    .expect("scenario path in client project")
                    .to_string_lossy()
                    .into_owned(),
            ));
        }
    }
    let jobs = std::env::var("BETTER_AUTH_COMPAT_JOBS").map_or_else(
        |_| {
            let output = Command::new("bash")
                .arg(project_root().join("scripts/compat-jobs.sh"))
                .output()
                .expect("compute host compatibility budget");
            assert!(output.status.success(), "host compatibility budget failed");
            String::from_utf8(output.stdout)
                .expect("compatibility budget UTF-8")
                .trim()
                .parse::<usize>()
                .expect("numeric compatibility budget")
        },
        |value| {
            value
                .parse::<usize>()
                .ok()
                .filter(|jobs| (1..=32).contains(jobs))
                .unwrap_or_else(|| panic!("BETTER_AUTH_COMPAT_JOBS must be between 1 and 32"))
        },
    );
    let mut files = Vec::new();
    for path in paths {
        collect(
            &project_root().join("tests/compat/client-tests").join(path),
            &mut files,
        );
    }
    // Warm complete-matrix measurements put cryptography and real protocol
    // waits first. New owners fall back to source size and are still discovered.
    let costs: std::collections::BTreeMap<String, u64> =
        serde_json::from_str(include_str!("scenario-costs.json")).expect("scenario cost estimates");
    files.sort_by(|left, right| {
        costs
            .get(&right.1)
            .unwrap_or(&right.0)
            .cmp(costs.get(&left.1).unwrap_or(&left.0))
            .then_with(|| left.1.cmp(&right.1))
    });
    files.dedup_by(|left, right| left.1 == right.1);
    assert!(
        !files.is_empty(),
        "no compatibility scenario files matched {paths:?}"
    );
    (
        jobs.min(files.len()),
        files.into_iter().map(|(_, path)| path).collect(),
    )
}

async fn run_client_compat(paths: &[&str]) {
    if paths == ["tests"] {
        check_compat_evidence(true);
    }
    let executable = build_rust_compat_server();
    if paths != ["environment"] {
        if paths.iter().all(|path| path.starts_with("tests")) {
            let coverage = paths == ["tests"];
            if coverage {
                reset_compat_evidence();
            }
            let (jobs, files) = scenario_files(paths);
            let work = std::sync::Mutex::new(std::collections::VecDeque::from(files));
            drop(writeln!(
                std::io::stderr().lock(),
                "Compatibility: {} isolated server pairs",
                jobs
            ));
            std::thread::scope(|scope| {
                let handles: Vec<_> = (0..jobs)
                    .map(|_| {
                        let executable = &executable;
                        let work = &work;
                        scope.spawn(move || {
                            let runtime = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("compatibility worker runtime");
                            runtime.block_on(run_client_compat_in_environment(
                                paths,
                                executable,
                                "production",
                                "false",
                                coverage,
                                Some(work),
                            ));
                        })
                    })
                    .collect();
                // Join every worker before propagating failures, allowing process
                // owners to clean up and coverage counters to flush on all shards.
                let mut failure = None;
                for handle in handles {
                    if let Err(error) = handle.join() {
                        failure = failure.or(Some(error));
                    }
                }
                if let Some(error) = failure {
                    std::panic::resume_unwind(error);
                }
            });
            if coverage {
                check_compat_evidence(false);
            }
        } else {
            run_client_compat_in_environment(
                paths,
                &executable,
                "production",
                "false",
                false,
                None,
            )
            .await;
        }
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
            run_client_compat_in_environment(
                &["environment"],
                &executable,
                node_env,
                test_flag,
                false,
                None,
            )
            .await;
        }
    }
}

async fn run_client_compat_in_environment(
    paths: &[&str],
    executable: &std::path::Path,
    node_env: &str,
    test_flag: &str,
    coverage: bool,
    work: Option<&std::sync::Mutex<std::collections::VecDeque<String>>>,
) {
    drop(writeln!(
        std::io::stderr().lock(),
        "Compatibility {paths:?}: NODE_ENV={node_env}, TEST={test_flag}"
    ));
    let ts_port = allocate_port();
    let rust_port = allocate_port();

    let mut ts_server =
        start_reference_server(ts_port, node_env, test_flag, paths == ["environment"]);
    // Configure process-owned TLS transport before native HTTP clients exist.
    wait_for_health(ts_port, &mut ts_server, Duration::from_secs(20)).await;
    let needs_salesforce = work.is_some()
        || paths.iter().any(|path| {
            matches!(*path, "tests" | "tests/core") || path.starts_with("tests/core/social")
        });
    let salesforce_proxy = if needs_salesforce {
        let response: serde_json::Value = reqwest::get(format!(
            "http://localhost:{ts_port}/__test/salesforce-transport/config"
        ))
        .await
        .expect("Salesforce transport configuration")
        .json()
        .await
        .expect("Salesforce transport JSON");
        Some(
            response
                .get("proxyURL")
                .and_then(serde_json::Value::as_str)
                .expect("Salesforce proxy URL")
                .to_owned(),
        )
    } else {
        None
    };
    let mut rust_server = start_rust_compat_server(
        rust_port,
        executable,
        node_env,
        test_flag,
        paths == ["environment"],
        salesforce_proxy.as_deref(),
    );

    wait_for_health(rust_port, &mut rust_server, Duration::from_secs(90)).await;

    if let Some(work) = work {
        loop {
            let next = work.lock().expect("scenario work queue").pop_front();
            let Some(path) = next else { break };
            run_bun_suite(
                &[&path],
                ts_port,
                rust_port,
                coverage,
                &mut ts_server,
                &mut rust_server,
            );
        }
    } else {
        run_bun_suite(
            paths,
            ts_port,
            rust_port,
            coverage,
            &mut ts_server,
            &mut rust_server,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One focused runner per scenario directory: `generated`, `core/<area>` and
    /// `plugins/<plugin>` under `client-tests/tests`.
    macro_rules! directory_runners {
        ($($name:ident => $directory:literal,)+) => {
            const DIRECTORIES: &[&str] = &[$($directory),+];

            $(
                #[tokio::test]
                #[ignore = "starts external TS and Rust servers"]
                async fn $name() {
                    run_client_compat(&[concat!("tests/", $directory)]).await;
                }
            )+
        };
    }

    directory_runners! {
        core_account_client_compat => "core/account",
        core_auth_client_compat => "core/auth",
        core_email_verification_client_compat => "core/email-verification",
        core_password_client_compat => "core/password",
        core_request_client_compat => "core/request",
        core_schema_client_compat => "core/schema",
        core_server_api_client_compat => "core/server-api",
        core_session_client_compat => "core/session",
        core_social_client_compat => "core/social",
        core_user_client_compat => "core/user",
        generated_client_compat => "generated",
        plugins_admin_client_compat => "plugins/admin",
        plugins_anonymous_client_compat => "plugins/anonymous",
        plugins_api_key_client_compat => "plugins/api-key",
        plugins_bearer_client_compat => "plugins/bearer",
        plugins_captcha_client_compat => "plugins/captcha",
        plugins_custom_session_client_compat => "plugins/custom-session",
        plugins_device_authorization_client_compat => "plugins/device-authorization",
        plugins_email_otp_client_compat => "plugins/email-otp",
        plugins_generic_oauth_client_compat => "plugins/generic-oauth",
        plugins_have_i_been_pwned_client_compat => "plugins/have-i-been-pwned",
        plugins_jwt_client_compat => "plugins/jwt",
        plugins_last_login_method_client_compat => "plugins/last-login-method",
        plugins_magic_link_client_compat => "plugins/magic-link",
        plugins_multi_session_client_compat => "plugins/multi-session",
        plugins_oauth_popup_client_compat => "plugins/oauth-popup",
        plugins_oauth_proxy_client_compat => "plugins/oauth-proxy",
        plugins_one_tap_client_compat => "plugins/one-tap",
        plugins_one_time_token_client_compat => "plugins/one-time-token",
        plugins_open_api_client_compat => "plugins/open-api",
        plugins_organization_client_compat => "plugins/organization",
        plugins_passkey_client_compat => "plugins/passkey",
        plugins_phone_number_client_compat => "plugins/phone-number",
        plugins_siwe_client_compat => "plugins/siwe",
        plugins_two_factor_client_compat => "plugins/two-factor",
        plugins_username_client_compat => "plugins/username",
    }

    #[test]
    fn every_scenario_directory_has_a_runner() {
        let root = project_root().join("tests/compat/client-tests/tests");
        let mut directories = vec!["generated".to_owned()];
        for group in ["core", "plugins"] {
            let path = root.join(group);
            for entry in std::fs::read_dir(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
            {
                let entry = entry.unwrap_or_else(|error| panic!("failed to read entry: {error}"));
                assert!(
                    entry.path().is_dir(),
                    "{} must hold directories only",
                    path.display()
                );
                directories.push(format!("{group}/{}", entry.file_name().to_string_lossy()));
            }
        }
        directories.sort();
        assert_eq!(directories, DIRECTORIES);
    }

    #[tokio::test]
    #[ignore = "starts external TS and Rust servers"]
    async fn full_client_compat() {
        run_client_compat(&["tests"]).await;
    }

    #[tokio::test]
    #[ignore = "starts external TS and Rust servers"]
    async fn core_client_compat() {
        run_client_compat(&["tests/core"]).await;
    }

    #[tokio::test]
    #[ignore = "starts external TS and Rust servers"]
    async fn plugins_client_compat() {
        run_client_compat(&["tests/plugins"]).await;
    }

    /// Runs the space-separated client-test paths in `BETTER_AUTH_COMPAT_PATHS`.
    #[tokio::test]
    #[ignore = "starts external TS and Rust servers"]
    async fn selected_client_compat() {
        let paths = std::env::var("BETTER_AUTH_COMPAT_PATHS")
            .unwrap_or_else(|_| panic!("BETTER_AUTH_COMPAT_PATHS must name client-test paths"));
        let paths: Vec<&str> = paths.split_whitespace().collect();
        assert!(
            !paths.is_empty(),
            "BETTER_AUTH_COMPAT_PATHS must name client-test paths"
        );
        run_client_compat(&paths).await;
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
}
