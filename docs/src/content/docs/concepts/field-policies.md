---
title: "Additional fields"
description: "Define input, storage, and output policies for application fields."
---

Additional fields define what clients can submit, what the store writes, and what public responses return. Add the corresponding model columns and migrations first.

## Declare a field

```rust
use better_auth::AuthConfig;
use better_auth::field_policy::FieldConfig;
use serde_json::json;

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret);
    config.user.additional_fields.insert(
        "locale".into(),
        FieldConfig::new(json!({ "type": "string" })).default_value(json!("en")),
    );
    config
}
```

Declare session and account fields through their respective `additional_fields` maps. `read_only()` rejects client input; `hidden()` omits the field from public output; `field_name()` maps it to a physical column.

Adapter transforms are awaited. Asynchronous endpoint validation is rejected, matching the pinned runtime. Public account output always removes credentials.

Trusted `AdapterRecord` snapshots can retain hidden fields and undefined values. Do not forward those snapshots as public responses. See [hooks](/concepts/hooks/) for write observations and the [field-policy source](https://github.com/cschmatzler/better-auth-rs/blob/main/crates/core/src/field_policy.rs) for validators and transforms.
