use std::collections::HashMap;

/// Calculate Shannon entropy of a byte slice
///
/// Returns value between 0.0 (no entropy) and 8.0 (maximum entropy)
/// Typical values:
/// - < 4.0: Very low (sparse data, English text)
/// - 4.0-6.0: Normal (typical code/data)
/// - 6.0-7.2: Elevated (compressed or obfuscated)
/// - > 7.2: High (encrypted or packed)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &byte in data {
        *freq.entry(byte).or_insert(0) += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for count in freq.values() {
        let p = *count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Calculate entropy using a sliding window
/// Returns Vec of (offset, entropy) tuples
pub fn sliding_window_entropy(data: &[u8], window_size: usize) -> Vec<(usize, f64)> {
    if data.len() < window_size {
        return vec![(0, calculate_entropy(data))];
    }

    let mut results = Vec::new();
    let step_size = window_size / 2; // 50% overlap

    for offset in (0..=data.len() - window_size).step_by(step_size) {
        let window = &data[offset..offset + window_size];
        let entropy = calculate_entropy(window);
        results.push((offset, entropy));
    }

    results
}

/// Classify entropy level
#[derive(Debug, PartialEq)]
pub enum EntropyLevel {
    VeryLow,  // < 4.0
    Normal,   // 4.0-6.0
    Elevated, // 6.0-7.2
    High,     // > 7.2
}

impl EntropyLevel {
    pub fn from_value(entropy: f64) -> Self {
        if entropy < 4.0 {
            EntropyLevel::VeryLow
        } else if entropy < 6.0 {
            EntropyLevel::Normal
        } else if entropy < 7.2 {
            EntropyLevel::Elevated
        } else {
            EntropyLevel::High
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            EntropyLevel::VeryLow => "very_low",
            EntropyLevel::Normal => "normal",
            EntropyLevel::Elevated => "elevated",
            EntropyLevel::High => "high",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            EntropyLevel::VeryLow => "Very low entropy (sparse data)",
            EntropyLevel::Normal => "Normal entropy (typical code/data)",
            EntropyLevel::Elevated => "Elevated entropy (possibly compressed or obfuscated)",
            EntropyLevel::High => "High entropy (likely encrypted or packed)",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let data = vec![0u8; 100];
        let entropy = calculate_entropy(&data);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_max_entropy() {
        // Uniform distribution should have high entropy
        let data: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.5); // Close to theoretical max of 8.0
    }

    #[test]
    fn test_text_entropy() {
        let data = b"Hello, World! This is a test string with some text.";
        let entropy = calculate_entropy(data);
        assert!(entropy > 3.0 && entropy < 6.0); // English text typically 4-5 bits
    }

    #[test]
    fn test_entropy_classification() {
        assert_eq!(EntropyLevel::from_value(2.5), EntropyLevel::VeryLow);
        assert_eq!(EntropyLevel::from_value(5.0), EntropyLevel::Normal);
        assert_eq!(EntropyLevel::from_value(6.5), EntropyLevel::Elevated);
        assert_eq!(EntropyLevel::from_value(7.5), EntropyLevel::High);
    }

    #[test]
    fn test_empty_data() {
        let data = vec![];
        let entropy = calculate_entropy(&data);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_sliding_window_entropy() {
        let data = vec![0u8; 200];
        let results = sliding_window_entropy(&data, 100);

        assert!(!results.is_empty());
        // All windows should have zero entropy since all bytes are the same
        for (_offset, entropy) in results {
            assert_eq!(entropy, 0.0);
        }
    }

    #[test]
    fn test_sliding_window_small_data() {
        let data = vec![1, 2, 3];
        let results = sliding_window_entropy(&data, 100);

        // Window larger than data should return single result
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 0);
    }

    #[test]
    fn test_entropy_level_as_str() {
        assert_eq!(EntropyLevel::VeryLow.as_str(), "very_low");
        assert_eq!(EntropyLevel::Normal.as_str(), "normal");
        assert_eq!(EntropyLevel::Elevated.as_str(), "elevated");
        assert_eq!(EntropyLevel::High.as_str(), "high");
    }

    #[test]
    fn test_entropy_level_description() {
        assert!(EntropyLevel::VeryLow.description().contains("Very low"));
        assert!(EntropyLevel::Normal.description().contains("Normal"));
        assert!(EntropyLevel::Elevated.description().contains("Elevated"));
        assert!(EntropyLevel::High.description().contains("High"));
    }

    #[test]
    fn test_entropy_boundary_conditions() {
        assert_eq!(EntropyLevel::from_value(3.99), EntropyLevel::VeryLow);
        assert_eq!(EntropyLevel::from_value(4.0), EntropyLevel::Normal);
        assert_eq!(EntropyLevel::from_value(5.99), EntropyLevel::Normal);
        assert_eq!(EntropyLevel::from_value(6.0), EntropyLevel::Elevated);
        assert_eq!(EntropyLevel::from_value(7.19), EntropyLevel::Elevated);
        assert_eq!(EntropyLevel::from_value(7.2), EntropyLevel::High);
    }

    #[test]
    fn test_sliding_window_overlap() {
        let data: Vec<u8> = (0..=255).cycle().take(500).collect();
        let results = sliding_window_entropy(&data, 100);

        // With 50% overlap, we should have multiple windows
        assert!(results.len() > 2);

        // Check that offsets are properly spaced
        if results.len() >= 2 {
            assert_eq!(results[1].0 - results[0].0, 50); // window_size / 2
        }
    }

    #[test]
    fn test_entropy_with_repeating_pattern() {
        let data = vec![0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB]; // Alternating pattern
        let entropy = calculate_entropy(&data);
        assert!(entropy > 0.9 && entropy < 1.1); // Should be close to 1.0 (2 equally likely values)
    }
}
