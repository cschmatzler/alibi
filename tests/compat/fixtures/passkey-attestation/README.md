These are public synthetic test CA keys. The acceptance fixture explicitly
configures the same root through Source SettingsService and Rust's per-format
trust configuration. Tests generate real leaf certificates, verify their
signatures, and submit genuine signed ceremonies. Default production roots are
not altered. The Source fixture restores default roots after each request.
