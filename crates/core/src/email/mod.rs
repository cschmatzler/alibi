use crate::error::AuthResult;
use async_trait::async_trait;
use std::io::Write;

/// Trait for sending emails. Implement this to integrate with your
/// email service (SMTP, `SendGrid`, SES, etc.).
#[async_trait]
pub trait EmailProvider: Send + Sync {
    /// Send an email.
    ///
    /// - `to`: recipient email address
    /// - `subject`: email subject line
    /// - `html`: HTML body (may be empty)
    /// - `text`: plain-text body (may be empty)
    async fn send(&self, to: &str, subject: &str, html: &str, text: &str) -> AuthResult<()>;
}

/// Development email provider that logs emails to stderr.
///
/// Useful for local development and testing — no external dependencies.
#[derive(Debug)]
pub struct ConsoleEmailProvider;

#[async_trait]
impl EmailProvider for ConsoleEmailProvider {
    async fn send(&self, to: &str, subject: &str, _html: &str, text: &str) -> AuthResult<()> {
        _ = writeln!(
            std::io::stderr().lock(),
            "[EMAIL] To: {to} | Subject: {subject} | Body: {text}"
        );
        Ok(())
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    type SentMessages = Arc<Mutex<Vec<(String, String, String, String)>>>;

    /// Mock email provider for testing.
    struct MockEmailProvider {
        sent: SentMessages,
    }

    impl MockEmailProvider {
        fn new() -> (Self, SentMessages) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    sent: Arc::clone(&sent),
                },
                sent,
            )
        }
    }

    #[async_trait]
    impl EmailProvider for MockEmailProvider {
        async fn send(&self, to: &str, subject: &str, html: &str, text: &str) -> AuthResult<()> {
            self.sent.lock().unwrap().push((
                to.to_owned(),
                subject.to_owned(),
                html.to_owned(),
                text.to_owned(),
            ));
            Ok(())
        }
    }

    // Rust-specific surface: Rust email provider helpers are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn test_console_email_provider_send() {
        let provider = ConsoleEmailProvider;
        let result = provider
            .send("user@example.com", "Test Subject", "<h1>Hi</h1>", "Hi")
            .await;
        assert!(result.is_ok());
    }

    // Rust-specific surface: Rust email provider helpers are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn test_mock_email_provider_records_sends() {
        let (provider, sent) = MockEmailProvider::new();
        provider
            .send("a@b.com", "Sub", "<p>html</p>", "text")
            .await
            .unwrap();
        provider.send("c@d.com", "Sub2", "", "text2").await.unwrap();

        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(
            (messages)
                .first()
                .expect("fixture contains the requested index")
                .0,
            "a@b.com"
        );
        assert_eq!(
            (messages)
                .get(1)
                .expect("fixture contains the requested index")
                .0,
            "c@d.com"
        );
    }

    // Rust-specific surface: Rust email provider helpers are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn test_trait_object_works() {
        let provider: Box<dyn EmailProvider> = Box::new(ConsoleEmailProvider);
        let result = provider.send("user@example.com", "Test", "", "body").await;
        assert!(result.is_ok());
    }

    // Rust-specific surface: Rust email provider helpers are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn test_missing_provider_returns_error() {
        use crate::plugin::AuthContext;
        use crate::test_store::{test_config, test_database};

        let config = test_config();
        let database = test_database().await;
        let ctx = AuthContext::new(config, database);

        let result = ctx.email_provider();
        assert!(result.is_err());
    }
}
// LCOV_EXCL_STOP
