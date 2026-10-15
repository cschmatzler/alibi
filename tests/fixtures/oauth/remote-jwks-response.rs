// External key-server responses; authentication and validation stay in the real provider.
pub(super) fn response(
    mode: &str,
    document: &serde_json::Value,
) -> (u16, Vec<(&'static str, &'static str)>, Vec<u8>) {
    use serde_json::json;
    let mut status = 200;
    let mut headers = vec![("content-type", "application/jwk-set+json; charset=utf-8")];
    let mut body = serde_json::to_vec(document).unwrap();
    match mode {
        "status" => status = 503,
        "redirect" => status = 302,
        "type" => headers = vec![("content-type", "text/plain")],
        "no-type" => headers.clear(),
        "length" => headers.push(("content-length", "65537")),
        "hex-length" => headers.push(("content-length", "0x10001")),
        "invalid-length" => headers.push(("content-length", "bogus")),
        "exact-body" => body.resize(65536, b' '),
        "over-body" => body.resize(65537, b' '),
        "bad-json" => body = b"invalid json".to_vec(),
        "empty-keys" => body = br#"{"keys":[]}"#.to_vec(),
        "symmetric" => body = br#"{"keys":[{"kty":"oct","k":"secret"}]}"#.to_vec(),
        "private-key" => {
            let mut key = document["keys"][0].clone();
            key["d"] = json!("secret");
            body = serde_json::to_vec(&json!({"keys":[key]})).unwrap();
        }
        "bom" => body.splice(..0, [0xef, 0xbb, 0xbf]).for_each(drop),
        "nonfinite" => {
            let mut value = document.clone();
            value["extra"] = json!("__nonfinite__");
            body = serde_json::to_string(&value)
                .unwrap()
                .replace("\"__nonfinite__\"", "1e400")
                .into_bytes();
        }
        "bad-utf8" => {
            let mut value = document.clone();
            value["extra"] = json!("x");
            let text = serde_json::to_string(&value).unwrap();
            let position = text.find("\"x\"").unwrap() + 1;
            body = text.into_bytes();
            body[position] = 255;
        }
        "wrong-kid" => {
            let mut key = document["keys"][0].clone();
            key["kid"] = json!("other");
            body = serde_json::to_vec(&json!({"keys":[key]})).unwrap();
        }
        "ambiguous" => {
            body = serde_json::to_vec(&json!({"keys":[document["keys"][0],document["keys"][0]]}))
                .unwrap()
        }
        _ => {}
    }
    (status, headers, body)
}
