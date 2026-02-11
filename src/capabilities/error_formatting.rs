//! Enhanced error formatting for YAML parsing errors.
//!
//! Provides user-friendly error messages with context, suggestions, and clear guidance.

use anyhow::Error;
use std::path::Path;

/// Enhance a YAML parsing error with context, suggestions, and clear guidance
pub fn enhance_yaml_error(error: &Error, file_path: &Path, yaml_content: &str) -> String {
    let error_string = format!("{:#}", error);

    // Extract line and column from serde_yaml error messages
    // Pattern: "at line X column Y"
    let (line_num, col_num) = extract_line_column(&error_string);

    let mut enhanced = String::new();
    enhanced.push_str(&format!("Failed to parse YAML in {:?}", file_path));

    // If we found line info, show context
    if let Some(line) = line_num {
        enhanced.push_str(&format!("\n\n   Error at line {}:", line));

        // Show context lines
        if let Some(context) = extract_yaml_context(yaml_content, line, col_num) {
            enhanced.push('\n');
            enhanced.push_str(&context);
        }

        // Analyze error and provide guidance
        if let Some(guidance) = provide_error_guidance(&error_string, yaml_content, line) {
            enhanced.push('\n');
            enhanced.push_str(&guidance);
        }
    } else {
        // No line info, just show the cleaned error
        enhanced.push_str(": ");
        enhanced.push_str(&clean_error_message(&error_string));
    }

    enhanced
}

/// Extract line and column numbers from error message
fn extract_line_column(error_msg: &str) -> (Option<usize>, Option<usize>) {
    // Look for "at line X column Y" pattern
    let line_regex = regex::Regex::new(r"at line (\d+) column (\d+)").unwrap();

    if let Some(caps) = line_regex.captures(error_msg) {
        let line = caps.get(1).and_then(|m| m.as_str().parse().ok());
        let col = caps.get(2).and_then(|m| m.as_str().parse().ok());
        return (line, col);
    }

    (None, None)
}

/// Extract and format YAML context around the error line
fn extract_yaml_context(
    yaml_content: &str,
    error_line: usize,
    error_col: Option<usize>,
) -> Option<String> {
    let lines: Vec<&str> = yaml_content.lines().collect();

    if error_line == 0 || error_line > lines.len() {
        return None;
    }

    // For ConditionDeser errors, try to find the actual "type:" line within the next few lines
    let actual_error_line = find_actual_error_line(&lines, error_line);

    let mut context = String::from("\n");

    // Show 2 lines before, error line, and 1 line after
    let start = actual_error_line.saturating_sub(3);
    let end = (actual_error_line + 1).min(lines.len());

    for i in start..end {
        let line_num = i + 1;
        let line_content = lines.get(i)?;

        if line_num == actual_error_line {
            // This is the error line - highlight it
            context.push_str(&format!("   {:>3}│{}", line_num, line_content));

            // Add error marker
            if let Some(col) = error_col {
                context.push('\n');
                let spaces = " ".repeat(7 + col);
                context.push_str(&format!("      │{}← Error here", spaces));
            } else {
                context.push_str("  ← Error here");
            }
        } else {
            context.push_str(&format!("   {:>3}│{}", line_num, line_content));
        }
        context.push('\n');
    }

    Some(context)
}

/// Find the actual error line by searching for "type:" within the trait definition
fn find_actual_error_line(lines: &[&str], reported_line: usize) -> usize {
    let start_idx = reported_line.saturating_sub(1);

    // Search next 15 lines for "type:" field
    for (i, &line) in lines
        .iter()
        .enumerate()
        .skip(start_idx)
        .take(15.min(lines.len().saturating_sub(start_idx)))
    {
        let line = line.trim_start();
        if line.starts_with("type:") {
            // Check if this is an invalid type
            if line.contains("type: word")
                || line.contains("type: text")
                || line.contains("type: function")
                || line.contains("type: regex")
            {
                return i + 1; // Return 1-indexed line number
            }
        }
    }

    // If not found, return original line
    reported_line
}

/// Clean up technical error messages for user consumption
fn clean_error_message(error_msg: &str) -> String {
    // Replace technical jargon with plain language
    let msg = error_msg
        .replace(
            "data did not match any variant of untagged enum ConditionDeser",
            "Invalid condition format",
        )
        .replace("unknown variant", "Invalid value")
        .replace("expected", "Expected");

    // Extract the most useful part
    if let Some(start) = msg.find("Invalid") {
        if let Some(end) = msg[start..].find(" at line") {
            return msg[start..start + end].to_string();
        }
        return msg[start..].split('\n').next().unwrap_or(&msg).to_string();
    }

    msg
}

/// Provide intelligent guidance based on the error type and context
fn provide_error_guidance(
    error_msg: &str,
    yaml_content: &str,
    error_line: usize,
) -> Option<String> {
    let lines: Vec<&str> = yaml_content.lines().collect();
    let error_line_idx = error_line.saturating_sub(1);

    let mut guidance = String::new();

    // Check for ConditionDeser error - means invalid condition type
    if error_msg.contains("ConditionDeser") || error_msg.contains("Invalid condition") {
        guidance.push_str("\n   Invalid condition type.\n");
        guidance.push_str("\n   Valid condition types:\n");
        guidance.push_str("   • symbol     - Match symbol names (functions, methods)\n");
        guidance.push_str("   • string     - Match string literals in the binary\n");
        guidance.push_str("   • trait      - Reference another trait by ID\n");
        guidance.push_str("   • yara_match - Match YARA rule results\n");
        guidance.push_str("   • ast        - Match AST patterns (requires tree-sitter)\n");
        guidance.push_str("   • syscall    - Match system calls\n");
        guidance.push_str("   • imports_count, exports_count, string_count\n");
        guidance.push_str("   • section_ratio, section_entropy, section_name\n");
        guidance.push_str("   • import_combination, metrics, hex, filesize\n");
        guidance.push_str("   • content, xor, basename, layer_path, kv\n");

        // Search nearby lines for common mistakes (since error line might be the item start)
        let search_start = error_line_idx;
        let search_end = (error_line_idx + 10).min(lines.len());
        let context_lines: Vec<&str> = lines[search_start..search_end].to_vec();
        let context = context_lines.join("\n");

        // Check for common mistakes in context
        if context.contains("type: word") {
            guidance.push_str("\n   💡 Did you mean 'type: string' instead of 'type: word'?\n");
            guidance.push_str("      Use 'string' type with 'word' field for word matching.\n");
        } else if context.contains("type: text") {
            guidance.push_str("\n   💡 Did you mean 'type: string' instead of 'type: text'?\n");
        } else if context.contains("type: function") {
            guidance.push_str("\n   💡 Did you mean 'type: symbol' instead of 'type: function'?\n");
        } else if context.contains("type: regex") {
            guidance.push_str("\n   💡 Use 'type: string' with 'regex' field, not 'type: regex'\n");
        }
    }

    // Check for missing 'type' field
    if error_msg.contains("missing field") && error_msg.contains("`type`") {
        guidance.push_str("\n   Missing 'type' field in condition.\n");
        guidance.push_str("\n   Either:\n");
        guidance.push_str("   • Add 'type:' field (symbol, string, trait, etc.)\n");
        guidance.push_str("   • Use shorthand format with just 'id:' for trait references\n");
    }

    // Check for invalid field names
    if error_msg.contains("unknown field") {
        if let Some(field_start) = error_msg.find("`") {
            if let Some(field_end) = error_msg[field_start + 1..].find("`") {
                let field_name = &error_msg[field_start + 1..field_start + 1 + field_end];
                guidance.push_str(&format!(
                    "\n   Unknown field '{}' in condition.\n",
                    field_name
                ));

                // Suggest corrections
                match field_name {
                    "match" => {
                        guidance.push_str("   💡 Did you mean 'exact', 'substr', or 'regex'?\n")
                    }
                    "pattern" => guidance.push_str("   💡 Did you mean 'regex' or 'substr'?\n"),
                    "value" => guidance.push_str("   💡 Did you mean 'exact' or 'word'?\n"),
                    "name" => guidance.push_str("   💡 Did you mean 'id' for trait references?\n"),
                    _ => {}
                }
            }
        }
    }

    if guidance.is_empty() {
        None
    } else {
        Some(guidance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_line_column() {
        let error = "some error at line 149 column 5";
        let (line, col) = extract_line_column(error);
        assert_eq!(line, Some(149));
        assert_eq!(col, Some(5));
    }

    #[test]
    fn test_clean_error_message() {
        let error = "data did not match any variant of untagged enum ConditionDeser at line 10";
        let cleaned = clean_error_message(error);
        assert!(cleaned.contains("Invalid condition format"));
        assert!(!cleaned.contains("untagged enum"));
    }
}
