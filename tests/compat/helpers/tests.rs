use super::html_text_content;

#[test]
fn html_text_content_decodes_entities_and_normalizes_whitespace() {
    assert_eq!(
        html_text_content("<div><span>CODE&#58;</span>&nbsp;<span>UNKNOWN</span></div>"),
        "CODE: UNKNOWN"
    );
    assert_eq!(
        html_text_content("<p>A&amp;B &lt;ok&gt; &#x26; &#38;</p>"),
        "A&B <ok> & &"
    );
}
