use a2a::{Message, Part, Role};
use proptest::prelude::*;
use smesh_a2a::{InputLimits, extract_text};

#[test]
fn extracts_inline_text_parts_in_order() {
    let message = Message::new(
        Role::User,
        vec![Part::text("review"), Part::text("src/lib.rs")],
    );

    let text = extract_text(&message, InputLimits::default()).unwrap();

    assert_eq!(text, "review\nsrc/lib.rs");
}

#[test]
fn rejects_empty_text() {
    let message = Message::new(Role::User, vec![Part::text("  ")]);

    let error = extract_text(&message, InputLimits::default()).unwrap_err();

    assert_eq!(error, smesh_a2a::InputError::Empty);
}

#[test]
fn rejects_non_text_parts_instead_of_fetching_them() {
    let message = Message::new(
        Role::User,
        vec![Part::url("http://169.254.169.254/latest/meta-data")],
    );

    let error = extract_text(&message, InputLimits::default()).unwrap_err();

    assert_eq!(error, smesh_a2a::InputError::UnsupportedPart);
}

#[test]
fn rejects_text_over_the_configured_byte_limit() {
    let message = Message::new(Role::User, vec![Part::text("four")]);
    let limits = InputLimits { max_text_bytes: 3 };

    let error = extract_text(&message, limits).unwrap_err();

    assert_eq!(
        error,
        smesh_a2a::InputError::TooLarge {
            actual: 4,
            limit: 3
        }
    );
}

proptest! {
    #[test]
    fn byte_limit_is_enforced_for_every_ascii_length(size in 1usize..256, limit in 0usize..256) {
        let text = "a".repeat(size);
        let message = Message::new(Role::User, vec![Part::text(text)]);
        let result = extract_text(&message, InputLimits { max_text_bytes: limit });

        prop_assert_eq!(result.is_ok(), size <= limit);
    }
}
