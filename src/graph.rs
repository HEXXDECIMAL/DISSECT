//! Graph visualization of trait relationships.
//!
//! Generates DOT (Graphviz) format showing directory-level trait dependencies.

use crate::capabilities::validation::collect_trait_refs_from_rule;
use crate::capabilities::CapabilityMapper;
use crate::types::Criticality;
use anyhow::Result;
use rustc_hash::FxHashMap;
use std::collections::HashMap;

/// Node in the dependency graph (represents a trait directory)
#[derive(Debug)]
struct GraphNode {
    /// Number of traits in this directory
    trait_count: usize,
    /// Highest criticality level found in this directory
    max_criticality: Criticality,
    /// Sum of all criticality values (for computing average)
    criticality_sum: f32,
}

impl GraphNode {
    fn average_criticality(&self) -> f32 {
        if self.trait_count == 0 {
            0.0
        } else {
            self.criticality_sum / self.trait_count as f32
        }
    }
}

/// Generate a DOT graph of trait relationships at directory level
pub fn generate_trait_graph(
    depth: usize,
    output_path: Option<&str>,
    min_refs: usize,
    namespace_filter: Option<&str>,
) -> Result<String> {
    // Load capability mapper to get all traits
    let mapper = CapabilityMapper::new();

    let mut nodes: FxHashMap<String, GraphNode> = FxHashMap::default();
    let mut edges: HashMap<(String, String), usize> = HashMap::new();

    // Parse namespace filter if provided
    let allowed_namespaces: Option<Vec<String>> =
        namespace_filter.map(|s| s.split(',').map(|ns| ns.trim().to_lowercase()).collect());

    // Process all composite rules to extract relationships
    for composite in mapper.composite_rules() {
        let source_dir = extract_directory(&composite.id, depth);

        // Skip if filtered by namespace
        if let Some(ref allowed) = allowed_namespaces {
            let top_level = source_dir.split('/').next().unwrap_or("");
            if !allowed.contains(&top_level.to_lowercase()) {
                continue;
            }
        }

        // Update source node
        let node = nodes.entry(source_dir.clone()).or_insert_with(|| GraphNode {
            trait_count: 0,
            max_criticality: Criticality::Filtered,
            criticality_sum: 0.0,
        });
        node.trait_count += 1;
        node.criticality_sum += criticality_to_f32(composite.crit);
        if composite.crit > node.max_criticality {
            node.max_criticality = composite.crit;
        }

        // Extract all trait references (returns Vec<(trait_id, rule_id)>)
        let trait_refs = collect_trait_refs_from_rule(composite);

        for (trait_ref, _rule_id) in trait_refs {
            let target_dir = extract_directory(&trait_ref, depth);

            // Skip self-references
            if target_dir == source_dir {
                continue;
            }

            // Skip if filtered by namespace
            if let Some(ref allowed) = allowed_namespaces {
                let top_level = target_dir.split('/').next().unwrap_or("");
                if !allowed.contains(&top_level.to_lowercase()) {
                    continue;
                }
            }

            // Ensure target node exists
            nodes.entry(target_dir.clone()).or_insert_with(|| GraphNode {
                trait_count: 0,
                max_criticality: Criticality::Filtered,
                criticality_sum: 0.0,
            });

            // Increment edge weight
            *edges.entry((source_dir.clone(), target_dir)).or_insert(0) += 1;
        }
    }

    // Generate DOT output
    let dot = generate_dot(&nodes, &edges, min_refs);

    // Write to file or stdout
    let message = if let Some(path) = output_path {
        std::fs::write(path, &dot)?;
        format!("Graph written to: {}", path)
    } else {
        dot
    };

    Ok(message)
}

/// Extract directory path up to specified depth
/// Example: "micro-behaviors/communications/socket/raw::trait-id" with depth=3 -> "micro-behaviors/communications/socket"
fn extract_directory(trait_id: &str, depth: usize) -> String {
    // Remove trait name after "::" if present
    let path_part = trait_id.split("::").next().unwrap_or(trait_id);

    // Split by '/' and take first N segments
    let segments: Vec<&str> = path_part.split('/').take(depth).collect();
    segments.join("/")
}

/// Convert Criticality to numeric value for averaging
fn criticality_to_f32(crit: Criticality) -> f32 {
    match crit {
        Criticality::Filtered => -1.0,
        Criticality::Inert => 0.0,
        Criticality::Notable => 1.0,
        Criticality::Suspicious => 2.0,
        Criticality::Hostile => 3.0,
    }
}

/// Get fill color based on average criticality
fn fill_color(avg_criticality: f32) -> &'static str {
    if avg_criticality < 0.5 {
        "#90EE90" // Light green (inert)
    } else if avg_criticality < 1.5 {
        "#FFFF99" // Light yellow (notable)
    } else if avg_criticality < 2.5 {
        "#FFA500" // Orange (suspicious)
    } else {
        "#FF6347" // Tomato red (hostile)
    }
}

/// Get outline color based on top-level namespace
fn outline_color(path: &str) -> &'static str {
    let top_level = path.split('/').next().unwrap_or("");
    match top_level {
        "micro-behaviors" => "#228B22",   // Forest green
        "objectives" => "#DC143C",   // Crimson red
        "well-known" => "#8B008B", // Dark magenta (purple)
        "metadata" => "#696969",  // Dim gray
        _ => "#000000",       // Black (fallback)
    }
}

/// Generate DOT format output
fn generate_dot(
    nodes: &FxHashMap<String, GraphNode>,
    edges: &HashMap<(String, String), usize>,
    min_refs: usize,
) -> String {
    let mut output = String::new();

    // Header
    output.push_str("digraph trait_dependencies {\n");
    output.push_str("  rankdir=LR;\n");
    output.push_str("  node [shape=box, style=\"filled,bold\", penwidth=3, fontname=\"Arial\"];\n");
    output.push_str("  edge [fontname=\"Arial\", fontsize=10];\n");
    output.push('\n');

    // Nodes
    for (path, node) in nodes {
        let avg_crit = node.average_criticality();
        let fill = fill_color(avg_crit);
        let outline = outline_color(path);
        let label = format!("{} ({})", shorten_path(path), node.trait_count);

        output.push_str(&format!(
            "  \"{}\" [fillcolor=\"{}\", color=\"{}\", label=\"{}\"];\n",
            path, fill, outline, label
        ));
    }

    output.push('\n');

    // Edges (filtered by min_refs)
    let mut edge_list: Vec<(&(String, String), &usize)> = edges.iter().collect();
    edge_list.sort_by(|a, b| b.1.cmp(a.1)); // Sort by weight descending

    for ((from, to), weight) in edge_list {
        if *weight >= min_refs {
            // Scale penwidth: 1-3 refs = 1, 4-7 = 2, 8-15 = 4, 16+ = 8
            let penwidth = if *weight >= 16 {
                8
            } else if *weight >= 8 {
                4
            } else if *weight >= 4 {
                2
            } else {
                1
            };

            output.push_str(&format!(
                "  \"{}\" -> \"{}\" [penwidth={}, label=\"{}\"];\n",
                from, to, penwidth, weight
            ));
        }
    }

    output.push_str("}\n");
    output
}

/// Shorten path for display (keep last 2-3 segments)
fn shorten_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() <= 2 {
        path.to_string()
    } else if let Some(last) = segments.last() {
        // Show first + last segments with ellipsis if too long
        format!("{}/.../{}", segments[0], last)
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_directory() {
        assert_eq!(
            extract_directory("micro-behaviors/communications/socket/raw::trait-id", 2),
            "micro-behaviors/communications"
        );
        assert_eq!(
            extract_directory("micro-behaviors/communications/socket/raw::trait-id", 3),
            "micro-behaviors/communications/socket"
        );
        assert_eq!(
            extract_directory("micro-behaviors/communications/socket/raw::trait-id", 4),
            "micro-behaviors/communications/socket/raw"
        );
        assert_eq!(extract_directory("micro-behaviors/communications/socket/raw::trait-id", 1), "micro-behaviors");

        // Without :: separator
        assert_eq!(extract_directory("micro-behaviors/communications/socket", 2), "micro-behaviors/communications");
        assert_eq!(extract_directory("micro-behaviors", 2), "micro-behaviors");
    }

    #[test]
    fn test_criticality_to_f32() {
        assert_eq!(criticality_to_f32(Criticality::Filtered), -1.0);
        assert_eq!(criticality_to_f32(Criticality::Inert), 0.0);
        assert_eq!(criticality_to_f32(Criticality::Notable), 1.0);
        assert_eq!(criticality_to_f32(Criticality::Suspicious), 2.0);
        assert_eq!(criticality_to_f32(Criticality::Hostile), 3.0);
    }

    #[test]
    fn test_fill_color() {
        assert_eq!(fill_color(0.0), "#90EE90"); // Inert
        assert_eq!(fill_color(0.4), "#90EE90"); // Inert
        assert_eq!(fill_color(1.0), "#FFFF99"); // Notable
        assert_eq!(fill_color(1.4), "#FFFF99"); // Notable
        assert_eq!(fill_color(2.0), "#FFA500"); // Suspicious
        assert_eq!(fill_color(2.4), "#FFA500"); // Suspicious
        assert_eq!(fill_color(2.8), "#FF6347"); // Hostile
        assert_eq!(fill_color(3.0), "#FF6347"); // Hostile
    }

    #[test]
    fn test_outline_color() {
        assert_eq!(outline_color("micro-behaviors/communications/socket"), "#228B22"); // Green
        assert_eq!(outline_color("objectives/command-and-control/beacon"), "#DC143C"); // Red
        assert_eq!(outline_color("well-known/malware/mirai"), "#8B008B"); // Purple
        assert_eq!(outline_color("metadata/lang"), "#696969"); // Gray
        assert_eq!(outline_color("unknown/namespace"), "#000000"); // Black fallback
    }

    #[test]
    fn test_shorten_path() {
        assert_eq!(shorten_path("micro-behaviors"), "micro-behaviors");
        assert_eq!(shorten_path("micro-behaviors/communications"), "micro-behaviors/communications");
        assert_eq!(shorten_path("micro-behaviors/communications/socket"), "micro-behaviors/.../socket");
        assert_eq!(shorten_path("micro-behaviors/communications/socket/raw"), "micro-behaviors/.../raw");
    }

    #[test]
    fn test_graph_node_average_criticality() {
        let node = GraphNode {
            trait_count: 4,
            max_criticality: Criticality::Suspicious,
            criticality_sum: 6.0, // (0 + 1 + 2 + 3) / 4 = 1.5
        };
        assert_eq!(node.average_criticality(), 1.5);

        // Empty node
        let empty_node = GraphNode {
            trait_count: 0,
            max_criticality: Criticality::Inert,
            criticality_sum: 0.0,
        };
        assert_eq!(empty_node.average_criticality(), 0.0);
    }
}
