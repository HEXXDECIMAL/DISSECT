use crate::analyzers::{detect_file_type, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Archive analyzer for .zip, .tar.gz, .tgz, etc.
pub struct ArchiveAnalyzer {
    max_depth: usize,
    current_depth: usize,
    capability_mapper: Option<CapabilityMapper>,
    yara_engine: Option<Arc<YaraEngine>>,
    /// Passwords to try for encrypted zip files
    zip_passwords: Vec<String>,
}

impl ArchiveAnalyzer {
    pub fn new() -> Self {
        Self {
            max_depth: 3,
            current_depth: 0,
            capability_mapper: None,
            yara_engine: None,
            zip_passwords: Vec::new(),
        }
    }

    pub fn with_depth(mut self, depth: usize) -> Self {
        self.current_depth = depth;
        self
    }

    pub fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Some(mapper);
        self
    }

    pub fn with_yara(mut self, engine: YaraEngine) -> Self {
        self.yara_engine = Some(Arc::new(engine));
        self
    }

    /// Set passwords to try for encrypted zip files
    pub fn with_zip_passwords(mut self, passwords: Vec<String>) -> Self {
        self.zip_passwords = passwords;
        self
    }

    fn analyze_archive(&self, file_path: &Path) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Prevent infinite recursion
        if self.current_depth >= self.max_depth {
            anyhow::bail!("Maximum archive depth ({}) exceeded", self.max_depth);
        }

        // Create temporary directory for extraction
        let temp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

        // Extract archive
        self.extract_archive(file_path, temp_dir.path())?;

        // Create target info
        let file_data = fs::read(file_path)?;
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: self.detect_archive_type(file_path).to_string(),
            size_bytes: file_data.len() as u64,
            sha256: self.calculate_sha256(&file_data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: format!("archive/{}", self.detect_archive_type(file_path)),
            description: format!("{} archive", self.detect_archive_type(file_path)),
            evidence: vec![Evidence {
                method: "extension".to_string(),
                source: "archive_analyzer".to_string(),
                value: file_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                location: None,
            }],
        });

        // Check if this is a JAR-like archive
        let is_jar = file_path.to_string_lossy().to_lowercase().ends_with(".jar")
            || file_path.to_string_lossy().to_lowercase().ends_with(".war")
            || file_path.to_string_lossy().to_lowercase().ends_with(".ear")
            || file_path.to_string_lossy().to_lowercase().ends_with(".apk")
            || file_path.to_string_lossy().to_lowercase().ends_with(".aar");

        if is_jar {
            self.analyze_jar_archive(temp_dir.path(), &mut report, start)?;
        } else {
            self.analyze_generic_archive(temp_dir.path(), &mut report, start)?;
        }

        Ok(report)
    }

    /// Analyze a JAR-like archive using YARA-first approach
    /// Only runs full Java bytecode parser on main class and YARA-flagged classes
    fn analyze_jar_archive(
        &self,
        temp_dir: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) -> Result<()> {
        // Find main class from MANIFEST.MF
        let main_class = self.find_main_class(temp_dir);
        if let Some(ref mc) = main_class {
            eprintln!("  Main-Class: {}", mc);
        }

        // Collect all files
        let all_files: Vec<_> = walkdir::WalkDir::new(temp_dir)
            .min_depth(1)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .collect();

        // Separate class files from non-class files
        let (class_files, other_files): (Vec<_>, Vec<_>) = all_files
            .into_iter()
            .partition(|e| e.path().extension().is_some_and(|ext| ext == "class"));

        let total_class_files = class_files.len();
        eprintln!("  Found {} .class files", total_class_files);

        // Phase 1: Run YARA on ALL class files in parallel (fast)
        let yara_flagged_classes = Arc::new(Mutex::new(HashSet::new()));
        let yara_matches = Arc::new(Mutex::new(Vec::new()));

        if let Some(ref yara_engine) = self.yara_engine {
            let yara_start = std::time::Instant::now();
            class_files.par_iter().for_each(|entry| {
                if let Ok(matches) = yara_engine.scan_file(entry.path()) {
                    if !matches.is_empty() {
                        // This class triggered YARA rules - mark for full analysis
                        yara_flagged_classes
                            .lock()
                            .unwrap()
                            .insert(entry.path().to_path_buf());

                        // Record the YARA matches
                        let mut all_matches = yara_matches.lock().unwrap();
                        for yara_match in matches {
                            if !all_matches
                                .iter()
                                .any(|m: &YaraMatch| m.rule == yara_match.rule)
                            {
                                all_matches.push(yara_match);
                            }
                        }
                    }
                }
            });
            eprintln!(
                "  YARA scan completed in {:.2}s",
                yara_start.elapsed().as_secs_f64()
            );
        }

        let flagged_classes = Arc::try_unwrap(yara_flagged_classes)
            .expect("YARA scan should be done")
            .into_inner()
            .unwrap();
        let collected_yara_matches = Arc::try_unwrap(yara_matches)
            .expect("YARA scan should be done")
            .into_inner()
            .unwrap();

        // Add collected YARA matches to report
        for ym in collected_yara_matches {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }

        eprintln!("  {} classes flagged by YARA", flagged_classes.len());

        // Phase 2: Run full JavaClassAnalyzer only on interesting classes
        // - Main class
        // - YARA-flagged classes
        // - Non-benign classes (limited sample)
        let interesting_classes: Vec<_> = class_files
            .iter()
            .filter(|e| {
                let path = e.path();
                let path_str = path.to_string_lossy();

                // Always analyze main class
                if let Some(ref mc) = main_class {
                    let class_path = mc.replace('.', "/") + ".class";
                    if path_str.ends_with(&class_path) {
                        return true;
                    }
                }

                // Always analyze YARA-flagged classes
                if flagged_classes.contains(path) {
                    return true;
                }

                // Skip benign library packages
                if Self::is_benign_java_path(path) {
                    return false;
                }

                // For non-flagged, non-benign classes, just take a sample
                false
            })
            .collect();

        // Also include a small sample of non-benign, non-flagged classes
        let sample_classes: Vec<_> = class_files
            .iter()
            .filter(|e| !Self::is_benign_java_path(e.path()) && !flagged_classes.contains(e.path()))
            .take(20) // Limit to 20 non-flagged classes
            .collect();

        let classes_to_analyze: Vec<_> = interesting_classes
            .into_iter()
            .chain(sample_classes)
            .collect();

        eprintln!("  Full analysis on {} classes", classes_to_analyze.len());

        // Run full analysis on selected classes
        let files_analyzed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let total_capabilities = Arc::new(Mutex::new(HashSet::new()));
        let total_traits = Arc::new(Mutex::new(HashSet::new()));
        let collected_traits = Arc::new(Mutex::new(Vec::<Finding>::new()));
        let collected_yara = Arc::new(Mutex::new(Vec::<YaraMatch>::new()));
        let collected_strings = Arc::new(Mutex::new(Vec::<StringInfo>::new()));

        classes_to_analyze.par_iter().for_each(|entry| {
            let archive_location = format!(
                "archive:{}",
                entry
                    .path()
                    .strip_prefix(temp_dir)
                    .unwrap_or(entry.path())
                    .display()
            );

            if let Ok(file_report) = self.analyze_extracted_file(entry.path()) {
                files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let mut caps = total_capabilities.lock().unwrap();
                let mut traits = total_traits.lock().unwrap();
                let mut all_traits = collected_traits.lock().unwrap();
                let mut all_yara = collected_yara.lock().unwrap();
                let mut all_strings = collected_strings.lock().unwrap();

                // Aggregate findings
                for f in &file_report.findings {
                    traits.insert(f.id.clone());
                    caps.insert(f.id.clone());
                    if !all_traits.iter().any(|existing| existing.id == f.id) {
                        let mut new_finding = f.clone();
                        for evidence in &mut new_finding.evidence {
                            evidence.location = Some(archive_location.clone());
                        }
                        all_traits.push(new_finding);
                    }
                }

                // Aggregate YARA matches
                for yara_match in file_report.yara_matches {
                    if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                        all_yara.push(yara_match);
                    }
                }

                // Aggregate interesting strings
                for string in file_report.strings {
                    if matches!(
                        string.string_type,
                        StringType::Url | StringType::Ip | StringType::Base64
                    ) {
                        all_strings.push(string);
                    }
                }
            }
        });

        // Phase 3: Analyze non-class files (scripts, configs, etc.)
        let non_class_files: Vec<_> = other_files
            .into_iter()
            .filter(|e| !Self::is_benign_java_path(e.path()))
            .filter(|e| {
                // Only analyze potentially interesting files
                let path_str = e.path().to_string_lossy().to_lowercase();
                !path_str.contains("meta-inf/")
                    || path_str.ends_with("manifest.mf")
                    || path_str.ends_with(".xml")
            })
            .take(100)
            .collect();

        non_class_files.par_iter().for_each(|entry| {
            let archive_location = format!(
                "archive:{}",
                entry
                    .path()
                    .strip_prefix(temp_dir)
                    .unwrap_or(entry.path())
                    .display()
            );

            // Run YARA on non-class files
            if let Some(ref yara_engine) = self.yara_engine {
                if let Ok(matches) = yara_engine.scan_file(entry.path()) {
                    let mut all_yara = collected_yara.lock().unwrap();
                    for yara_match in matches {
                        if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                            all_yara.push(yara_match);
                        }
                    }
                }
            }

            // Run file-type-specific analysis
            if let Ok(file_report) = self.analyze_extracted_file(entry.path()) {
                files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let mut caps = total_capabilities.lock().unwrap();
                let mut traits = total_traits.lock().unwrap();
                let mut all_traits = collected_traits.lock().unwrap();
                let mut all_yara = collected_yara.lock().unwrap();
                let mut all_strings = collected_strings.lock().unwrap();

                // Aggregate findings
                for f in &file_report.findings {
                    traits.insert(f.id.clone());
                    caps.insert(f.id.clone());
                    if !all_traits.iter().any(|existing| existing.id == f.id) {
                        let mut new_finding = f.clone();
                        for evidence in &mut new_finding.evidence {
                            evidence.location = Some(archive_location.clone());
                        }
                        all_traits.push(new_finding);
                    }
                }

                // Aggregate YARA matches
                for yara_match in file_report.yara_matches {
                    if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                        all_yara.push(yara_match);
                    }
                }

                // Aggregate interesting strings
                for string in file_report.strings {
                    if matches!(
                        string.string_type,
                        StringType::Url | StringType::Ip | StringType::Base64
                    ) {
                        all_strings.push(string);
                    }
                }
            }
        });

        // Merge collected results into the report
        let total_capabilities = Arc::try_unwrap(total_capabilities)
            .expect("All parallel tasks should be done")
            .into_inner()
            .unwrap();
        let total_traits = Arc::try_unwrap(total_traits)
            .expect("All parallel tasks should be done")
            .into_inner()
            .unwrap();
        let files_analyzed = files_analyzed.load(std::sync::atomic::Ordering::Relaxed);

        for t in Arc::try_unwrap(collected_traits)
            .expect("done")
            .into_inner()
            .unwrap()
        {
            if !report.findings.iter().any(|existing| existing.id == t.id) {
                report.findings.push(t);
            }
        }
        for ym in Arc::try_unwrap(collected_yara)
            .expect("done")
            .into_inner()
            .unwrap()
        {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }
        report.strings.extend(
            Arc::try_unwrap(collected_strings)
                .expect("done")
                .into_inner()
                .unwrap(),
        );

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "JAR archive: {} total classes, {} YARA-flagged, {} fully analyzed, {} traits and {} capabilities detected",
            total_class_files,
            flagged_classes.len(),
            files_analyzed,
            total_traits.len(),
            total_capabilities.len()
        ));

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec![
            "archive_analyzer".to_string(),
            "yara".to_string(),
            "java_class_analyzer".to_string(),
        ];

        Ok(())
    }

    /// Analyze a generic (non-JAR) archive
    fn analyze_generic_archive(
        &self,
        temp_dir: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) -> Result<()> {
        // Collect all files to analyze
        let files: Vec<_> = walkdir::WalkDir::new(temp_dir)
            .min_depth(1)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .take(500)
            .collect();
        let total_files = files.len();
        eprintln!("  Analyzing {} files", total_files);

        // Create thread-safe containers for aggregated results
        let files_processed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let files_analyzed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let total_capabilities = Arc::new(Mutex::new(HashSet::new()));
        let total_traits = Arc::new(Mutex::new(HashSet::new()));
        let collected_traits = Arc::new(Mutex::new(Vec::<Finding>::new()));
        let collected_yara = Arc::new(Mutex::new(Vec::<YaraMatch>::new()));
        let collected_strings = Arc::new(Mutex::new(Vec::<StringInfo>::new()));
        let last_progress = Arc::new(Mutex::new(std::time::Instant::now()));

        // Analyze files in parallel
        files.par_iter().for_each(|entry| {
            // Track progress
            let processed = files_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if let Ok(mut last) = last_progress.try_lock() {
                if last.elapsed() > std::time::Duration::from_secs(1) {
                    let analyzed = files_analyzed.load(std::sync::atomic::Ordering::Relaxed);
                    eprintln!(
                        "  Progress: {}/{} files processed, {} analyzed",
                        processed, total_files, analyzed
                    );
                    *last = std::time::Instant::now();
                }
            }

            let archive_location = format!(
                "archive:{}",
                entry
                    .path()
                    .strip_prefix(temp_dir)
                    .unwrap_or(entry.path())
                    .display()
            );

            // Run YARA scan on extracted file if engine is available
            if let Some(ref yara_engine) = self.yara_engine {
                if let Ok(matches) = yara_engine.scan_file(entry.path()) {
                    let mut all_yara = collected_yara.lock().unwrap();
                    for yara_match in matches {
                        if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                            all_yara.push(yara_match);
                        }
                    }
                }
            }

            if let Ok(file_report) = self.analyze_extracted_file(entry.path()) {
                files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let mut caps = total_capabilities.lock().unwrap();
                let mut traits = total_traits.lock().unwrap();
                let mut all_traits = collected_traits.lock().unwrap();
                let mut all_yara = collected_yara.lock().unwrap();
                let mut all_strings = collected_strings.lock().unwrap();

                // Aggregate findings
                for f in &file_report.findings {
                    traits.insert(f.id.clone());
                    caps.insert(f.id.clone());
                    if !all_traits.iter().any(|existing| existing.id == f.id) {
                        let mut new_finding = f.clone();
                        for evidence in &mut new_finding.evidence {
                            evidence.location = Some(archive_location.clone());
                        }
                        all_traits.push(new_finding);
                    }
                }

                // Aggregate YARA matches
                for yara_match in file_report.yara_matches {
                    if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                        all_yara.push(yara_match);
                    }
                }

                // Aggregate interesting strings
                for string in file_report.strings {
                    if matches!(
                        string.string_type,
                        StringType::Url | StringType::Ip | StringType::Base64
                    ) {
                        all_strings.push(string);
                    }
                }
            }
        });

        // Merge collected results into the report
        let total_capabilities = Arc::try_unwrap(total_capabilities)
            .expect("All parallel tasks should be done")
            .into_inner()
            .unwrap();
        let total_traits = Arc::try_unwrap(total_traits)
            .expect("All parallel tasks should be done")
            .into_inner()
            .unwrap();
        let files_analyzed = files_analyzed.load(std::sync::atomic::Ordering::Relaxed);

        for t in Arc::try_unwrap(collected_traits)
            .expect("done")
            .into_inner()
            .unwrap()
        {
            if !report.findings.iter().any(|existing| existing.id == t.id) {
                report.findings.push(t);
            }
        }
        for ym in Arc::try_unwrap(collected_yara)
            .expect("done")
            .into_inner()
            .unwrap()
        {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }
        report.strings.extend(
            Arc::try_unwrap(collected_strings)
                .expect("done")
                .into_inner()
                .unwrap(),
        );

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "Archive contains {} files analyzed, {} traits and {} capabilities detected",
            files_analyzed,
            total_traits.len(),
            total_capabilities.len()
        ));

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["archive_analyzer".to_string(), "walkdir".to_string()];

        Ok(())
    }

    /// Extract main class from META-INF/MANIFEST.MF
    fn find_main_class(&self, temp_dir: &Path) -> Option<String> {
        let manifest_path = temp_dir.join("META-INF/MANIFEST.MF");
        if !manifest_path.exists() {
            return None;
        }

        let file = File::open(&manifest_path).ok()?;
        let reader = BufReader::new(file);

        for line in reader.lines().map_while(Result::ok) {
            if line.starts_with("Main-Class:") {
                return Some(line.trim_start_matches("Main-Class:").trim().to_string());
            }
        }
        None
    }

    fn extract_archive(&self, archive_path: &Path, dest_dir: &Path) -> Result<()> {
        let archive_type = self.detect_archive_type(archive_path);

        match archive_type {
            "zip" => self.extract_zip(archive_path, dest_dir),
            "tar" => self.extract_tar(archive_path, dest_dir, None),
            "tar.gz" | "tgz" => self.extract_tar(archive_path, dest_dir, Some("gzip")),
            "tar.bz2" | "tbz" | "tbz2" => self.extract_tar(archive_path, dest_dir, Some("bzip2")),
            "tar.xz" | "txz" => self.extract_tar(archive_path, dest_dir, Some("xz")),
            "xz" => self.extract_compressed(archive_path, dest_dir, "xz"),
            "gz" => self.extract_compressed(archive_path, dest_dir, "gzip"),
            "bz2" => self.extract_compressed(archive_path, dest_dir, "bzip2"),
            _ => anyhow::bail!("Unsupported archive type: {}", archive_type),
        }
    }

    fn extract_compressed(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        compression: &str,
    ) -> Result<()> {
        let file = File::open(archive_path)?;

        // Determine output filename by stripping the compression extension
        let stem = archive_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("extracted");
        let output_path = dest_dir.join(stem);

        let mut output_file = File::create(&output_path).context("Failed to create output file")?;

        match compression {
            "xz" => {
                let mut decoder = xz2::read::XzDecoder::new(file);
                std::io::copy(&mut decoder, &mut output_file)
                    .context("Failed to decompress XZ file")?;
            }
            "gzip" => {
                let mut decoder = flate2::read::GzDecoder::new(file);
                std::io::copy(&mut decoder, &mut output_file)
                    .context("Failed to decompress GZ file")?;
            }
            "bzip2" => {
                let mut decoder = bzip2::read::BzDecoder::new(file);
                std::io::copy(&mut decoder, &mut output_file)
                    .context("Failed to decompress BZ2 file")?;
            }
            _ => anyhow::bail!("Unsupported compression: {}", compression),
        }

        Ok(())
    }

    fn extract_zip(&self, archive_path: &Path, dest_dir: &Path) -> Result<()> {
        let file = File::open(archive_path)?;
        let mut archive = zip::ZipArchive::new(file).context("Failed to read ZIP archive")?;

        // Check if the archive is encrypted by trying to read the first file
        let is_encrypted = if !archive.is_empty() {
            match archive.by_index(0) {
                Ok(entry) => entry.encrypted(),
                Err(_) => true, // If we can't read, assume it needs a password
            }
        } else {
            false
        };

        if is_encrypted && !self.zip_passwords.is_empty() {
            // Try each password
            for password in &self.zip_passwords {
                // Re-open the archive for each password attempt
                let file = File::open(archive_path)?;
                let mut archive =
                    zip::ZipArchive::new(file).context("Failed to read ZIP archive")?;

                match self.extract_zip_with_password(&mut archive, dest_dir, password.as_bytes()) {
                    Ok(()) => {
                        eprintln!("  Decrypted with password: {}", password);
                        return Ok(());
                    }
                    Err(_) => continue,
                }
            }
            anyhow::bail!(
                "Password required to decrypt file (tried {} passwords)",
                self.zip_passwords.len()
            );
        }

        // Try without password
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let outpath = dest_dir.join(entry.name());

            if entry.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut outfile = File::create(&outpath)?;
                std::io::copy(&mut entry, &mut outfile)?;
            }
        }

        Ok(())
    }

    fn extract_zip_with_password(
        &self,
        archive: &mut zip::ZipArchive<File>,
        dest_dir: &Path,
        password: &[u8],
    ) -> Result<()> {
        for i in 0..archive.len() {
            let mut entry = archive.by_index_decrypt(i, password)?;
            let outpath = dest_dir.join(entry.name());

            if entry.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut outfile = File::create(&outpath)?;
                std::io::copy(&mut entry, &mut outfile)?;
            }
        }
        Ok(())
    }

    fn extract_tar(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        compression: Option<&str>,
    ) -> Result<()> {
        let file = File::open(archive_path)?;

        let mut archive: tar::Archive<Box<dyn Read>> = match compression {
            Some("gzip") => {
                let decoder = flate2::read::GzDecoder::new(file);
                tar::Archive::new(Box::new(decoder))
            }
            Some("bzip2") => {
                let decoder = bzip2::read::BzDecoder::new(file);
                tar::Archive::new(Box::new(decoder))
            }
            Some("xz") => {
                let decoder = xz2::read::XzDecoder::new(file);
                tar::Archive::new(Box::new(decoder))
            }
            None => tar::Archive::new(Box::new(file)),
            _ => anyhow::bail!("Unsupported compression: {:?}", compression),
        };

        archive
            .unpack(dest_dir)
            .context("Failed to extract TAR archive")?;

        Ok(())
    }

    fn analyze_extracted_file(&self, file_path: &Path) -> Result<AnalysisReport> {
        // Detect file type
        let file_type = detect_file_type(file_path)?;

        // Route to appropriate analyzer with capability mapper if available
        match file_type {
            crate::analyzers::FileType::MachO => {
                let mut analyzer = crate::analyzers::macho::MachOAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Elf => {
                let mut analyzer = crate::analyzers::elf::ElfAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Pe => {
                let mut analyzer = crate::analyzers::pe::PEAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Shell => {
                let mut analyzer = crate::analyzers::shell::ShellAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Python => {
                let mut analyzer = crate::analyzers::python::PythonAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::JavaScript => {
                let mut analyzer = crate::analyzers::javascript::JavaScriptAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::JavaClass => {
                let mut analyzer = crate::analyzers::java_class::JavaClassAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Java => {
                let analyzer = crate::analyzers::java::JavaAnalyzer::new();
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Ruby => {
                let analyzer = crate::analyzers::ruby::RubyAnalyzer::new();
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::VsixManifest => {
                let mut analyzer = crate::analyzers::vsix_manifest::VsixManifestAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            _ => {
                // Skip unknown files
                Err(anyhow::anyhow!("Unsupported file type"))
            }
        }
    }

    /// Check if a path is from a known benign Java package (common libraries)
    fn is_benign_java_path(path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        // Skip common library packages
        path_str.contains("/com/google/")
            || path_str.contains("/org/apache/")
            || path_str.contains("/org/slf4j/")
            || path_str.contains("/org/json/")
            || path_str.contains("/org/xml/")
            || path_str.contains("/javax/")
            || path_str.contains("/org/w3c/")
            || path_str.contains("/org/bouncycastle/")
            || path_str.contains("/org/junit/")
            || path_str.contains("/org/mockito/")
            || path_str.contains("/com/fasterxml/")
            || path_str.contains("/org/gradle/")
            || path_str.contains("/org/jetbrains/")
            || path_str.contains("/kotlin/")
            || path_str.contains("/scala/")
            || path_str.contains("/io/netty/")
            || path_str.contains("/okhttp3/")
            || path_str.contains("/okio/")
            || path_str.contains("/com/squareup/")
            || path_str.contains("/org/springframework/")
            || path_str.contains("/ch/qos/")
            || path_str.contains("/org/hibernate/")
            || path_str.contains("/com/sun/")
            || path_str.contains("/sun/")
            || path_str.contains("/jdk/")
            || path_str.contains("/java/")
            || path_str.contains("/com/oracle/")
            || path_str.contains("/io/grpc/")
            || path_str.contains("/com/amazonaws/")
            || path_str.contains("/software/amazon/")
            || path_str.contains("/org/eclipse/")
            || path_str.contains("/groovy/")
            || path_str.contains("/org/codehaus/")
            || path_str.contains("/io/micrometer/")
            || path_str.contains("/org/reactivestreams/")
            || path_str.contains("/reactor/")
            || path_str.contains("/org/yaml/")
            || path_str.contains("/org/hamcrest/")
            || path_str.contains("/org/assertj/")
            || path_str.contains("/org/objectweb/")
            || path_str.contains("/net/bytebuddy/")
            || path_str.contains("/org/objenesis/")
            || path_str.contains("/antlr/")
            || path_str.contains("/org/antlr/")
            || path_str.contains("/org/checkerframework/")
            || path_str.contains("/META-INF/")
            || path_str.contains("/joptsimple/")
            || path_str.contains("/oshi/")
            || path_str.contains("/com/typesafe/")
            || path_str.contains("/io/prometheus/")
            || path_str.contains("/javassist/")
            || path_str.contains("/net/java/")
            || path_str.contains("/ibm/icu/")
            || path_str.contains("/com/ibm/")
    }

    fn detect_archive_type(&self, path: &Path) -> &str {
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.ends_with(".tar.gz") {
            "tar.gz"
        } else if path_str.ends_with(".tgz") {
            "tgz"
        } else if path_str.ends_with(".tar.bz2") {
            "tar.bz2"
        } else if path_str.ends_with(".tbz2") || path_str.ends_with(".tbz") {
            "tbz"
        } else if path_str.ends_with(".tar.xz") {
            "tar.xz"
        } else if path_str.ends_with(".txz") {
            "txz"
        } else if path_str.ends_with(".tar") {
            "tar"
        } else if path_str.ends_with(".zip")
            || path_str.ends_with(".jar")
            || path_str.ends_with(".war")
            || path_str.ends_with(".ear")
            || path_str.ends_with(".apk")
            || path_str.ends_with(".aar")
        {
            "zip"
        } else if path_str.ends_with(".xz") {
            "xz"
        } else if path_str.ends_with(".gz") {
            "gz"
        } else if path_str.ends_with(".bz2") {
            "bz2"
        } else {
            "unknown"
        }
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Default for ArchiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ArchiveAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        self.analyze_archive(file_path)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        let path_str = file_path.to_string_lossy().to_lowercase();
        path_str.ends_with(".zip")
            || path_str.ends_with(".jar")
            || path_str.ends_with(".war")
            || path_str.ends_with(".ear")
            || path_str.ends_with(".apk")
            || path_str.ends_with(".aar")
            || path_str.ends_with(".tar")
            || path_str.ends_with(".tar.gz")
            || path_str.ends_with(".tgz")
            || path_str.ends_with(".tar.bz2")
            || path_str.ends_with(".tbz2")
            || path_str.ends_with(".tar.xz")
            || path_str.ends_with(".txz")
            || (path_str.ends_with(".xz") && !path_str.ends_with(".tar.xz"))
            || (path_str.ends_with(".gz") && !path_str.ends_with(".tar.gz"))
            || (path_str.ends_with(".bz2") && !path_str.ends_with(".tar.bz2"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_new() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.max_depth, 3);
        assert_eq!(analyzer.current_depth, 0);
    }

    #[test]
    fn test_default() {
        let analyzer = ArchiveAnalyzer::default();
        assert_eq!(analyzer.max_depth, 3);
        assert_eq!(analyzer.current_depth, 0);
    }

    #[test]
    fn test_with_depth() {
        let analyzer = ArchiveAnalyzer::new().with_depth(5);
        assert_eq!(analyzer.current_depth, 5);
    }

    #[test]
    fn test_can_analyze_zip() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.zip")));
        assert!(analyzer.can_analyze(Path::new("TEST.ZIP")));
    }

    #[test]
    fn test_can_analyze_jar() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.jar")));
        assert!(analyzer.can_analyze(Path::new("TEST.JAR")));
        assert!(analyzer.can_analyze(Path::new("test.war")));
        assert!(analyzer.can_analyze(Path::new("test.apk")));
    }

    #[test]
    fn test_detect_archive_type_jar() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("test.jar")), "zip");
        assert_eq!(analyzer.detect_archive_type(Path::new("test.war")), "zip");
        assert_eq!(analyzer.detect_archive_type(Path::new("test.apk")), "zip");
    }

    #[test]
    fn test_can_analyze_tar() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.tar")));
        assert!(analyzer.can_analyze(Path::new("test.tar.gz")));
        assert!(analyzer.can_analyze(Path::new("test.tgz")));
    }

    #[test]
    fn test_can_analyze_tar_bz2() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.tar.bz2")));
        assert!(analyzer.can_analyze(Path::new("test.tbz2")));
    }

    #[test]
    fn test_can_analyze_tar_xz() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.tar.xz")));
        assert!(analyzer.can_analyze(Path::new("test.txz")));
    }

    #[test]
    fn test_cannot_analyze_other() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(!analyzer.can_analyze(Path::new("test.txt")));
        assert!(!analyzer.can_analyze(Path::new("test.elf")));
    }

    #[test]
    fn test_detect_archive_type_zip() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("test.zip")), "zip");
    }

    #[test]
    fn test_detect_archive_type_tar() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("test.tar")), "tar");
    }

    #[test]
    fn test_detect_archive_type_tar_gz() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("test.tar.gz")),
            "tar.gz"
        );
        assert_eq!(analyzer.detect_archive_type(Path::new("test.tgz")), "tgz");
    }

    #[test]
    fn test_detect_archive_type_tar_bz2() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("test.tar.bz2")),
            "tar.bz2"
        );
        assert_eq!(analyzer.detect_archive_type(Path::new("test.tbz2")), "tbz");
        assert_eq!(analyzer.detect_archive_type(Path::new("test.tbz")), "tbz");
    }

    #[test]
    fn test_detect_archive_type_tar_xz() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("test.tar.xz")),
            "tar.xz"
        );
        assert_eq!(analyzer.detect_archive_type(Path::new("test.txz")), "txz");
    }

    #[test]
    fn test_detect_archive_type_unknown() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("test.txt")),
            "unknown"
        );
    }

    #[test]
    fn test_calculate_sha256() {
        let analyzer = ArchiveAnalyzer::new();
        let data = b"test data";
        let hash = analyzer.calculate_sha256(data);
        assert_eq!(hash.len(), 64); // SHA256 is 64 hex characters
        assert_eq!(
            hash,
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_analyze_zip_with_shell_script() {
        // Create a test ZIP with a shell script inside
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("test.zip");

        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("test.sh", options).unwrap();
        zip.write_all(b"#!/bin/sh\necho 'hello'").unwrap();
        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&zip_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.target.file_type, "zip");
        assert!(report
            .structure
            .iter()
            .any(|s| s.id.starts_with("archive/")));
    }

    #[test]
    fn test_max_depth_exceeded() {
        let analyzer = ArchiveAnalyzer::new().with_depth(3);

        // Create a temporary ZIP file
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("test.zip");

        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("dummy.txt", options).unwrap();
        zip.write_all(b"test").unwrap();
        zip.finish().unwrap();

        let result = analyzer.analyze(&zip_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Maximum archive depth"));
    }

    #[test]
    fn test_with_zip_passwords() {
        let passwords = vec!["pass1".to_string(), "pass2".to_string()];
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(passwords.clone());
        assert_eq!(analyzer.zip_passwords, passwords);
    }

    #[test]
    fn test_with_zip_passwords_empty_by_default() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.zip_passwords.is_empty());
    }

    #[test]
    fn test_encrypted_zip_with_correct_password() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip with password "secret"
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"secret");
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with correct password
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec!["secret".to_string()]);
        let result = analyzer.analyze(&zip_path);
        assert!(result.is_ok(), "Should decrypt with correct password");
    }

    #[test]
    fn test_encrypted_zip_with_wrong_password() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip with password "secret"
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"secret");
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with wrong password
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec!["wrongpass".to_string()]);
        let result = analyzer.analyze(&zip_path);
        assert!(result.is_err(), "Should fail with wrong password");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("tried 1 passwords"));
    }

    #[test]
    fn test_encrypted_zip_no_passwords_configured() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"secret");
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with no passwords (default)
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&zip_path);
        assert!(result.is_err(), "Should fail when no passwords configured");
    }

    #[test]
    fn test_encrypted_zip_multiple_passwords_finds_correct() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip with password "correct"
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"correct");
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with multiple passwords, correct one is third
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec![
            "wrong1".to_string(),
            "wrong2".to_string(),
            "correct".to_string(),
            "wrong3".to_string(),
        ]);
        let result = analyzer.analyze(&zip_path);
        assert!(
            result.is_ok(),
            "Should find correct password among multiple"
        );
    }

    #[test]
    fn test_unencrypted_zip_works_with_passwords_configured() {
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("unencrypted.zip");

        // Create unencrypted zip
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Should work even with passwords configured
        let analyzer = ArchiveAnalyzer::new()
            .with_zip_passwords(vec!["pass1".to_string(), "pass2".to_string()]);
        let result = analyzer.analyze(&zip_path);
        assert!(
            result.is_ok(),
            "Unencrypted zip should work with passwords configured"
        );
    }

    #[test]
    fn test_extract_zip_with_password_helper() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");
        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        // Create encrypted zip
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"testpass");
        zip.start_file("data.txt", options).unwrap();
        zip.write_all(b"secret data").unwrap();
        zip.finish().unwrap();

        // Test the extract helper directly
        let analyzer = ArchiveAnalyzer::new();
        let file = File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let result = analyzer.extract_zip_with_password(&mut archive, &extract_dir, b"testpass");
        assert!(result.is_ok(), "Should extract with correct password");

        // Verify file was extracted
        let extracted_file = extract_dir.join("data.txt");
        assert!(extracted_file.exists(), "Extracted file should exist");
        let bytes = fs::read(&extracted_file).unwrap();
        let content = String::from_utf8_lossy(&bytes);
        assert_eq!(content, "secret data");
    }
}
