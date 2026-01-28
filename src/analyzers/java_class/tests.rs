#[cfg(test)]
mod tests {
    use crate::analyzers::{java_class::JavaClassAnalyzer, Analyzer};
    use std::path::Path;

    #[test]
    fn test_can_analyze_class_extension() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("Test.class")));
    }

    #[test]
    fn test_cannot_analyze_other_extension() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(!analyzer.can_analyze(Path::new("test.java")));
    }

    #[test]
    fn test_major_version_mapping() {
        assert_eq!(JavaClassAnalyzer::major_to_java_version(52), "8");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(55), "11");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(61), "17");
    }
}
