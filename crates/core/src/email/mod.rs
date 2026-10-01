#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::error::AuthResult;

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
        drop(writeln!(
            std::io::stderr().lock(),
            "[EMAIL] To: {to} | Subject: {subject} | Body: {text}"
        ));
        Ok(())
    }
}
