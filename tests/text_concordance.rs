use a2a::{Message, Part, Role};
use smesh_a2a::{
    TextConcordanceError, TextConcordanceInputError, TextConcordanceLimits,
    extract_text_concordance_input, process_text_concordance,
};

fn generous_limits() -> TextConcordanceLimits {
    TextConcordanceLimits {
        max_input_bytes: 65_536,
        max_line_count: 65_537,
        max_ascii_word_count: 32_768,
        max_word_frequency: 32_768,
        max_artifact_bytes: 1_048_576,
    }
}

fn message(parts: Vec<Part>) -> Message {
    Message::new(Role::User, parts)
}

#[test]
fn strict_input_accepts_empty_and_preserves_exact_text() {
    assert_eq!(
        extract_text_concordance_input(&message(vec![Part::text("")]), 8).unwrap(),
        ""
    );
    assert_eq!(
        extract_text_concordance_input(&message(vec![Part::text(" \t\r\n")]), 8).unwrap(),
        " \t\r\n"
    );
}

#[test]
fn strict_input_rejects_missing_multiple_and_non_text_parts() {
    assert_eq!(
        extract_text_concordance_input(&message(vec![]), 8),
        Err(TextConcordanceInputError::PartCount)
    );
    assert_eq!(
        extract_text_concordance_input(&message(vec![Part::text("a"), Part::text("b")]), 8),
        Err(TextConcordanceInputError::PartCount)
    );
    assert_eq!(
        extract_text_concordance_input(&message(vec![Part::data(serde_json::json!({}))]), 8),
        Err(TextConcordanceInputError::UnsupportedPart)
    );
}

#[test]
fn strict_input_rejects_descriptive_extensions_and_part_decorations() {
    let mut decorated_part = Part::text("a");
    decorated_part.filename = Some("ignored.txt".to_owned());
    assert_eq!(
        extract_text_concordance_input(&message(vec![decorated_part]), 8),
        Err(TextConcordanceInputError::PartDecorations)
    );

    let mut extended_message = message(vec![Part::text("a")]);
    extended_message.extensions = Some(vec!["urn:example".to_owned()]);
    assert_eq!(
        extract_text_concordance_input(&extended_message, 8),
        Err(TextConcordanceInputError::MessageExtensions)
    );
}

#[test]
fn strict_input_enforces_exact_utf8_byte_bound() {
    assert_eq!(
        extract_text_concordance_input(&message(vec![Part::text("é")]), 2).unwrap(),
        "é"
    );
    assert_eq!(
        extract_text_concordance_input(&message(vec![Part::text("é")]), 1),
        Err(TextConcordanceInputError::InputBytesExceeded)
    );
}

#[test]
fn empty_input_golden_vector_is_byte_exact() {
    let output = process_text_concordance("", generous_limits()).unwrap();
    let expected = concat!(
        r#"{"schema":"text-concordance/v1","input_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","utf8_bytes":0,"line_count":0,"ascii_word_count":0,"word_frequencies":{}}"#,
        "\n",
    );

    assert_eq!(
        output.request_digest,
        "sha256:f8df8242b7894d1166d404218930698acd5de75edc3c2c4a58a267bbe801917a"
    );
    assert_eq!(output.artifact_bytes, expected.as_bytes());
    assert_eq!(
        output.artifact_digest,
        "sha256:8801f3b3b8a4dc9b1c3fe6bfdd0cb18c89f3e14e74f8eb1fb8643ddd0c71e9f7"
    );
    assert_eq!(
        output.artifact_set_digest,
        "sha256:18e63707d9135ec4decdb63429a3aa559149f218b929d7330e04d5cd9014f548"
    );
    assert_eq!(output.manifest.name, "text-concordance.v1.json");
    assert_eq!(output.manifest.media_type, "application/json");
    assert_eq!(output.manifest.digest, output.artifact_digest);
}

#[test]
fn mixed_utf8_crlf_golden_vector_is_byte_exact() {
    let input = "Hello, HELLO!\nworld\r\ncafé_ABC";
    let output = process_text_concordance(input, generous_limits()).unwrap();
    let expected = concat!(
        r#"{"schema":"text-concordance/v1","input_sha256":"29368bf2118e461f2f2c9cc38fd9cab9acc844a5e06bbcac67829d944265b2cf","utf8_bytes":30,"line_count":3,"ascii_word_count":5,"word_frequencies":{"abc":1,"caf":1,"hello":2,"world":1}}"#,
        "\n",
    );

    assert_eq!(
        output.request_digest,
        "sha256:b9a606c28c2fbfef025ce035804a2412853407a14374b5a5a368cf640d42f224"
    );
    assert_eq!(output.artifact_bytes, expected.as_bytes());
    assert_eq!(
        output.artifact_digest,
        "sha256:62a3284702a129710ca400d9efc17878d5263c6134f015545541c52c6271bf36"
    );
    assert_eq!(
        output.artifact_set_digest,
        "sha256:55731fae80f0e37258f6ac7951470b15b39bb83ad9171d757d8aacf31b276329"
    );
}

#[test]
fn terminal_lf_does_not_add_an_empty_line() {
    let output = process_text_concordance("alpha\n", generous_limits()).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.artifact_bytes).unwrap();
    assert_eq!(json["line_count"], 1);
}

#[test]
fn ascii_words_are_byte_delimited_lowercased_and_sorted() {
    let output = process_text_concordance("Zoo-zoo Élan apple APPLE", generous_limits()).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.artifact_bytes).unwrap();
    assert_eq!(json["ascii_word_count"], 5);
    assert_eq!(
        json["word_frequencies"],
        serde_json::json!({"apple": 2, "lan": 1, "zoo": 2})
    );
    let text = std::str::from_utf8(&output.artifact_bytes).unwrap();
    assert!(text.contains(r#""word_frequencies":{"apple":2,"lan":1,"zoo":2}"#));
}

#[test]
fn changed_input_changes_exact_identity_even_when_words_normalize_equally() {
    let lower = process_text_concordance("a", generous_limits()).unwrap();
    let upper = process_text_concordance("A", generous_limits()).unwrap();

    assert_eq!(
        lower.request_digest,
        "sha256:88eda50bb1500545ba6f0eae69af2983e1a977d37a3da7db254fa418d4a07dec"
    );
    assert_eq!(
        upper.request_digest,
        "sha256:4bf95e601d2aabdaae3b59ea775710847231c5b477f9b215ed814f2ca852ad68"
    );
    assert_ne!(lower.request_digest, upper.request_digest);
    assert_ne!(lower.artifact_digest, upper.artifact_digest);
    assert_ne!(lower.artifact_set_digest, upper.artifact_set_digest);
}

#[test]
fn every_declared_bound_accepts_exactly_and_rejects_one_over() {
    let exact = TextConcordanceLimits {
        max_input_bytes: 3,
        max_line_count: 1,
        max_ascii_word_count: 1,
        max_word_frequency: 1,
        max_artifact_bytes: 195,
    };
    let output = process_text_concordance("abc", exact).unwrap();
    assert_eq!(output.artifact_bytes.len(), 195);

    let cases = [
        (
            "abcd",
            TextConcordanceLimits {
                max_input_bytes: 3,
                ..generous_limits()
            },
            TextConcordanceError::InputBytesExceeded,
        ),
        (
            "a\nb",
            TextConcordanceLimits {
                max_line_count: 1,
                ..generous_limits()
            },
            TextConcordanceError::LineCountExceeded,
        ),
        (
            "a b",
            TextConcordanceLimits {
                max_ascii_word_count: 1,
                ..generous_limits()
            },
            TextConcordanceError::AsciiWordCountExceeded,
        ),
        (
            "a a",
            TextConcordanceLimits {
                max_word_frequency: 1,
                ..generous_limits()
            },
            TextConcordanceError::WordFrequencyExceeded,
        ),
        (
            "abc",
            TextConcordanceLimits {
                max_artifact_bytes: 194,
                ..generous_limits()
            },
            TextConcordanceError::ArtifactBytesExceeded,
        ),
    ];

    for (input, limits, expected) in cases {
        assert_eq!(process_text_concordance(input, limits), Err(expected));
    }
}
