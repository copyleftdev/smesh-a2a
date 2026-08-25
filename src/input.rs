use a2a::{Message, PartContent};
use thiserror::Error;

/// Public-input bounds enforced before work reaches the mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputLimits {
    pub max_text_bytes: usize,
}

impl Default for InputLimits {
    fn default() -> Self {
        Self {
            max_text_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InputError {
    #[error("message contains no text")]
    Empty,
    #[error("only inline text parts are supported")]
    UnsupportedPart,
    #[error("message is {actual} bytes; limit is {limit}")]
    TooLarge { actual: usize, limit: usize },
}

/// Extract inline text in wire order.
///
/// # Errors
///
/// Returns [`InputError`] when no usable text is present, a non-text part
/// is present, or the configured byte limit is exceeded.
pub fn extract_text(message: &Message, limits: InputLimits) -> Result<String, InputError> {
    let mut output = String::new();
    let mut first = true;

    for part in &message.parts {
        let PartContent::Text(text) = &part.content else {
            return Err(InputError::UnsupportedPart);
        };
        let separator_bytes = usize::from(!first);
        let actual = output
            .len()
            .checked_add(separator_bytes)
            .and_then(|size| size.checked_add(text.len()))
            .unwrap_or(usize::MAX);
        if actual > limits.max_text_bytes {
            return Err(InputError::TooLarge {
                actual,
                limit: limits.max_text_bytes,
            });
        }
        if !first {
            output.push('\n');
        }
        output.push_str(text);
        first = false;
    }

    if output.trim().is_empty() {
        return Err(InputError::Empty);
    }

    Ok(output)
}
