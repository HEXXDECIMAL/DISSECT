use streaming_iterator::StreamingIterator;

fn main() {
    let source: &[u8] = b"import os\nresult = os.popen(\"ls\")\n";

    let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&lang).unwrap();

    let tree = parser.parse(source, None).unwrap();

    // Query with CORRECT predicate syntax (wrapped)
    println!("=== Query for os.utime with CORRECT syntax ===");
    let query_utime = tree_sitter::Query::new(
        &lang,
        r#"
((call
  function: (attribute
    object: (identifier) @mod
    attribute: (identifier) @meth))
 (#eq? @mod "os")
 (#eq? @meth "utime"))
"#,
    )
    .unwrap();

    println!("Pattern count: {}", query_utime.pattern_count());

    let mut cursor = tree_sitter::QueryCursor::new();
    let mut buffer1 = Vec::new();
    let mut buffer2 = Vec::new();

    struct TextProvider<'a>(&'a [u8]);
    impl<'a> tree_sitter::TextProvider<&'a [u8]> for TextProvider<'a> {
        type I = std::iter::Once<&'a [u8]>;
        fn text(&mut self, node: tree_sitter::Node) -> Self::I {
            let start = node.byte_range().start;
            let end = node.byte_range().end.min(self.0.len());
            std::iter::once(&self.0[start..end])
        }
    }

    let mut matches = cursor.matches(&query_utime, tree.root_node(), source);
    let mut count = 0;
    while let Some(m) = matches.next() {
        if m.captures.is_empty() {
            continue;
        }
        let mut tp = TextProvider(source);
        let passes = m.satisfies_text_predicates(&query_utime, &mut buffer1, &mut buffer2, &mut tp);
        count += 1;
        println!("Match {}: passes_predicates={}", count, passes);
        for cap in m.captures {
            let text = std::str::from_utf8(&source[cap.node.byte_range()]).unwrap_or("?");
            println!(
                "  @{}: '{}'",
                query_utime.capture_names()[cap.index as usize],
                text
            );
        }
    }
    println!("Total matches for os.utime: {}", count);

    // Now test os.popen query
    println!("\n=== Query for os.popen with CORRECT syntax ===");
    let query_popen = tree_sitter::Query::new(
        &lang,
        r#"
((call
  function: (attribute
    object: (identifier) @mod
    attribute: (identifier) @meth))
 (#eq? @mod "os")
 (#eq? @meth "popen"))
"#,
    )
    .unwrap();

    let mut cursor2 = tree_sitter::QueryCursor::new();
    let mut matches2 = cursor2.matches(&query_popen, tree.root_node(), source);
    let mut count2 = 0;
    while let Some(m) = matches2.next() {
        if m.captures.is_empty() {
            continue;
        }
        let mut tp = TextProvider(source);
        let passes = m.satisfies_text_predicates(&query_popen, &mut buffer1, &mut buffer2, &mut tp);
        count2 += 1;
        println!("Match {}: passes_predicates={}", count2, passes);
        for cap in m.captures {
            let text = std::str::from_utf8(&source[cap.node.byte_range()]).unwrap_or("?");
            println!(
                "  @{}: '{}'",
                query_popen.capture_names()[cap.index as usize],
                text
            );
        }
    }
    println!("Total matches for os.popen: {}", count2);
}
