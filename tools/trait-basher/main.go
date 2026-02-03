// trait-basher orchestrates AI to tune DISSECT trait definitions.
//
// It scans a directory with dissect and invokes an AI assistant (Claude, Gemini,
// or Opencode) to analyze findings and modify/create traits as needed.
//
// Usage:
//
//	trait-basher --dir /path/to/good-samples --good
//	trait-basher --dir /path/to/malware-samples --bad
//	trait-basher --dir /path/to/samples --bad --provider gemini
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const knownGoodPrompt = `Fix false positive trait matches in this KNOWN-GOOD file.

File: %s
Expected: This file is KNOWN-GOOD (legitimate software)
Problem: DISSECT flagged it as suspicious/hostile - these are false positives

## Your Task
1. Run: ` + "`dissect %s --format jsonl`" + ` to see the current findings
2. Read RULES.md and TAXONOMY.md for syntax/taxonomy reference
3. Analyze what the file actually does (read it, understand its purpose)
4. For each finding that doesn't match actual behavior, fix using ONE of (in priority order):
   a) TAXONOMY: Move trait to correct location (e.g., cap/comm/http/client not obj/c2/beacon)
   b) PATTERNS: Make regex/match more specific; use cap/comm/http/ (directory) or cap/comm/http/client (exact)
   c) EXCLUSIONS: Add ` + "`not:`" + ` conditions to filter this case
   d) EXCEPTIONS: Add ` + "`unless:`" + ` or ` + "`downgrade:`" + ` (last resort)
5. Validate: Run dissect again - all findings should match actual capabilities

## Debug Commands
` + "```" + `
dissect test-rules <file> --rules "rule-id"           # why does rule match/fail?
dissect test-match <file> --type string --pattern X   # test individual conditions
` + "```" + `

Traits: %s/traits/ | Reorganize don't delete | Skip cargo test | Only analyze this file`

const knownBadPrompt = `Add missing detection for this KNOWN-BAD malware sample.

File: %s
Expected: This file is KNOWN-BAD (malware)
Problem: DISSECT did not flag it as suspicious/hostile - detection is missing

NOTE: If file is genuinely benign (README, docs, unmodified dependency), skip it.

## Your Task
1. Run: ` + "`dissect %s --format jsonl`" + ` to see the current findings
2. Read RULES.md and TAXONOMY.md for syntax/taxonomy reference
3. Reverse engineer: radare2, nm, strings, objdump, xxd - identify malicious capabilities
4. Create/modify traits using GENERIC behavioral patterns (not file-specific signatures):
   - cap/ = neutral mechanics (socket, exec, file ops) - capabilities that could be benign
   - obj/ = attacker intent (combine caps: socket + exec → reverse-shell) - malicious objectives
   - known/ = ONLY for specific malware family names (e.g., known/malware/apt/cozy-bear, known/malware/trojan/emotet)
   - Cross-language when possible (base64+exec works in Python, JS, Shell)
   - Trait refs: use obj/exec/ to match directory (all exec-type objectives) or obj/exec/shell for exact, avoids obfuscation brittleness
5. Validate: Run dissect again - should be suspicious or hostile

## Debug Commands
` + "```" + `
dissect test-rules <file> --rules "rule-id"           # why does rule match/fail?
dissect test-match <file> --type string --pattern X   # test individual conditions
` + "```" + `

Traits: %s/traits/ | Skip cargo test | Only analyze this file`

const knownGoodArchivePrompt = `Fix false positive trait matches in this KNOWN-GOOD archive.

Archive: %s
Expected: This archive is KNOWN-GOOD (legitimate software)
Problem: %d members flagged as suspicious/hostile - these are false positives

## Your Task
1. Run: ` + "`dissect %s --format jsonl`" + ` to see the current findings for all members
2. Read RULES.md and TAXONOMY.md for syntax/taxonomy reference
3. Focus on problematic members (the ones with suspicious/hostile findings)
4. For each false positive finding, fix using ONE of (in priority order):
   a) TAXONOMY: Move trait to correct location (e.g., cap/comm/http/client not obj/c2/beacon)
   b) PATTERNS: Make regex/match more specific; use cap/comm/http/ (directory) or cap/comm/http/client (exact)
   c) EXCLUSIONS: Add ` + "`not:`" + ` conditions to filter this case
   d) EXCEPTIONS: Add ` + "`unless:`" + ` or ` + "`downgrade:`" + ` (last resort)
5. Validate: Run dissect again - all findings should match actual capabilities

## Debug Commands
` + "```" + `
dissect test-rules <file> --rules "rule-id"           # why does rule match/fail?
dissect test-match <file> --type string --pattern X   # test individual conditions
` + "```" + `

Traits: %s/traits/ | Reorganize don't delete | Skip cargo test | Focus on this archive`

const knownBadArchivePrompt = `Add missing detection for this KNOWN-BAD malware archive.

Archive: %s
Expected: This archive is KNOWN-BAD (malware)
Problem: %d members not flagged as suspicious/hostile - detection is missing

NOTE: If some files are genuinely benign (README, docs, unmodified dependencies), skip them.

## Your Task
1. Run: ` + "`dissect %s --format jsonl`" + ` to see the current findings for all members
2. Read RULES.md and TAXONOMY.md for syntax/taxonomy reference
3. Focus on problematic members (the ones WITHOUT suspicious/hostile findings)
4. Reverse engineer: radare2, nm, strings, objdump, xxd - identify malicious capabilities
5. Create/modify traits using GENERIC behavioral patterns (not file-specific signatures):
   - cap/ = neutral mechanics (socket, exec, file ops) - capabilities that could be benign
   - obj/ = attacker intent (combine caps: socket + exec → reverse-shell) - malicious objectives
   - known/ = ONLY for specific malware family names (e.g., known/malware/apt/cozy-bear, known/malware/trojan/emotet)
   - Cross-language when possible (base64+exec works in Python, JS, Shell)
   - Trait refs: use obj/exec/ to match directory (all exec-type objectives) or obj/exec/shell for exact, avoids obfuscation brittleness
6. Validate: Run dissect again - should be suspicious or hostile

## Debug Commands
` + "```" + `
dissect test-rules <file> --rules "rule-id"           # why does rule match/fail?
dissect test-match <file> --type string --pattern X   # test individual conditions
` + "```" + `

Traits: %s/traits/ | Skip cargo test | Focus on this archive`

type config struct {
	db        *sql.DB
	dir       string
	repoRoot  string
	provider  string
	model     string
	sampleDir string
	timeout   time.Duration
	knownGood bool
	knownBad  bool
	useCargo  bool
	flush     bool
}

// Finding represents a matched trait/capability.
type Finding struct {
	ID   string `json:"id"`
	Crit string `json:"crit"`
	Desc string `json:"desc"`
}

// FileAnalysis represents a single analyzed file.
type FileAnalysis struct {
	Path          string    `json:"path"`
	Risk          string    `json:"risk"`
	ExtractedPath string    `json:"extracted_path,omitempty"`
	Findings      []Finding `json:"findings"`
}

// ArchiveAnalysis groups files from the same archive for review as a unit.
// Archives are the unit of resolution - a bad tar.gz with 100 good files and
// 1 bad file should be reviewed as a single archive.
type ArchiveAnalysis struct {
	ArchivePath string
	Members     []FileAnalysis
}

// RealFileAnalysis groups a real file with all its encoded/decoded fragments.
// Fragments are decoded payloads (e.g., base64-decoded content) that should be
// analyzed together with their parent file.
type RealFileAnalysis struct {
	RealPath  string         // The real file path (stripped of ## fragment delimiters)
	Root      FileAnalysis   // The root/real file entry
	Fragments []FileAnalysis // All decoded fragment entries (if any)
}

// archiveExtraction holds information about an extracted archive.
type archiveExtraction struct {
	path    string   // Path to extracted archive directory
	members []string // List of member paths in the archive
}

// extractArchive extracts an archive to a destination directory and returns member list.
// Supports: .zip, .tar.gz, .tgz, .7z, .xz
func extractArchive(ctx context.Context, archivePath, destDir string) (*archiveExtraction, error) {
	ext := strings.ToLower(filepath.Ext(archivePath))

	// Check for compound extensions
	base := strings.ToLower(filepath.Base(archivePath))
	if strings.HasSuffix(base, ".tar.gz") || strings.HasSuffix(base, ".tgz") {
		ext = ".tar.gz"
	}

	switch ext {
	case ".zip":
		return extractZip(archivePath, destDir)
	case ".tar.gz", ".tgz":
		return extractTarGz(archivePath, destDir)
	case ".7z":
		return extract7z(ctx, archivePath, destDir)
	case ".xz":
		return extractXz(ctx, archivePath, destDir)
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", ext)
	}
}

// extractZip extracts a ZIP archive.
func extractZip(archivePath, destDir string) (*archiveExtraction, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer reader.Close()

	var members []string
	for _, f := range reader.File {
		path := filepath.Join(destDir, f.Name)

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0o755); err != nil {
				return nil, fmt.Errorf("create directory: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create directory: %w", err)
		}

		src, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open file in zip: %w", err)
		}

		dst, err := os.Create(path)
		if err != nil {
			src.Close() //nolint:errcheck
			return nil, fmt.Errorf("create extracted file: %w", err)
		}

		if _, err := io.Copy(dst, src); err != nil {
			src.Close()  //nolint:errcheck
			dst.Close() //nolint:errcheck
			return nil, fmt.Errorf("extract file: %w", err)
		}
		src.Close()  //nolint:errcheck
		dst.Close() //nolint:errcheck

		members = append(members, f.Name)
	}

	return &archiveExtraction{path: destDir, members: members}, nil
}

// extractTarGz extracts a tar.gz archive.
func extractTarGz(archivePath, destDir string) (*archiveExtraction, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open tar.gz: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var members []string

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}

		path := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return nil, fmt.Errorf("create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return nil, fmt.Errorf("create directory: %w", err)
			}
			dst, err := os.Create(path)
			if err != nil {
				return nil, fmt.Errorf("create extracted file: %w", err)
			}
			if _, err := io.CopyN(dst, tr, header.Size); err != nil {
				dst.Close() //nolint:errcheck
				return nil, fmt.Errorf("extract file: %w", err)
			}
			dst.Close() //nolint:errcheck
			members = append(members, header.Name)
		}
	}

	return &archiveExtraction{path: destDir, members: members}, nil
}

// extract7z extracts a 7z archive using the `7z` command-line tool.
// Tries common malware archive passwords: "infected", "infect3d"
func extract7z(ctx context.Context, archivePath, destDir string) (*archiveExtraction, error) {
	passwords := []string{"", "infected", "infect3d"}
	var lastErr error

	for _, pwd := range passwords {
		args := []string{"x", "-o" + destDir, "-y"}
		if pwd != "" {
			args = append(args, "-p"+pwd)
		}
		args = append(args, archivePath)

		cmd := exec.CommandContext(ctx, "7z", args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err == nil {
			// Success - list the extracted files
			members, err := listDir(destDir)
			if err != nil {
				return nil, err
			}
			return &archiveExtraction{path: destDir, members: members}, nil
		}
		lastErr = errors.New(stderr.String())
	}

	if lastErr != nil {
		return nil, fmt.Errorf("extract 7z (all passwords failed): %w", lastErr)
	}
	return nil, errors.New("extract 7z failed")
}

// extractXz extracts an .xz file using the `xz` command-line tool.
func extractXz(ctx context.Context, archivePath, destDir string) (*archiveExtraction, error) {
	// For .xz, decompress to a file
	base := filepath.Base(archivePath)
	outputPath := filepath.Join(destDir, strings.TrimSuffix(base, ".xz"))

	cmd := exec.CommandContext(ctx, "xz", "-d", "-c", archivePath)

	out, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("create output file: %w", err)
	}
	defer out.Close()

	cmd.Stdout = out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("extract xz: %w (%s)", err, stderr.String())
	}

	members := []string{filepath.Base(outputPath)}
	return &archiveExtraction{path: destDir, members: members}, nil
}

// listDir recursively lists all files in a directory.
func listDir(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			files = append(files, rel)
		}
		return nil
	})
	return files, err
}

// archiveMemberStats finds the most notable file (with highest risk) and largest file.
func archiveMemberStats(archive *ArchiveAnalysis) (mostNotable, largest *FileAnalysis) {
	riskRank := map[string]int{"inert": 0, "notable": 1, "suspicious": 2, "hostile": 3}
	maxRisk := -1

	for i, m := range archive.Members {
		// Find most notable
		for _, f := range m.Findings {
			rank := riskRank[strings.ToLower(f.Crit)]
			if rank > maxRisk {
				maxRisk = rank
				mostNotable = &archive.Members[i]
			}
		}

		// Find largest (by extracted path size if available)
		if largest == nil {
			largest = &archive.Members[i]
		} else if m.ExtractedPath != "" && largest.ExtractedPath != "" {
			sizeM, errM := getFileSize(m.ExtractedPath)
			sizeL, errL := getFileSize(largest.ExtractedPath)
			if errM == nil && errL == nil && sizeM > sizeL {
				largest = &archive.Members[i]
			}
		}
	}

	return
}

// getFileSize returns the size of a file.
func getFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// rootArchive returns the root archive path from a path with archive delimiters.
// e.g., "archive.zip!!inner/file.py" -> "archive.zip".
// For non-archive paths, returns empty string.
func rootArchive(path string) string {
	if idx := strings.Index(path, "!!"); idx != -1 {
		return path[:idx]
	}
	return ""
}

// memberPath returns the member path within an archive,
// e.g., "archive.zip!!inner/file.py" -> "inner/file.py".
func memberPath(path string) string {
	if idx := strings.Index(path, "!!"); idx != -1 {
		return path[idx+2:]
	}
	return path
}

// realFilePath returns the real file path, stripping fragment delimiters.
// e.g., "yarn_fragments.sh##base64@0" -> "yarn_fragments.sh".
// For non-fragment paths, returns the original path.
func realFilePath(path string) string {
	if idx := strings.Index(path, "##"); idx != -1 {
		return path[:idx]
	}
	return path
}

// isFragment returns true if this path represents an encoded/decoded fragment.
func isFragment(path string) bool {
	return strings.Contains(path, "##")
}

// archiveNeedsReview returns true if any member of the archive needs review.
// For known-good archives: review if ANY member is flagged (to reduce false positives).
// For known-bad archives: review if ANY member is NOT yet flagged (to find missing detections).
func archiveNeedsReview(a *ArchiveAnalysis, knownGood bool) bool {
	// Review if ANY member needs review
	for _, m := range a.Members {
		if needsReview(m, knownGood) {
			return true
		}
	}
	return false
}

// archiveProblematicMembers returns the members that need review.
func archiveProblematicMembers(a *ArchiveAnalysis, knownGood bool) []FileAnalysis {
	var result []FileAnalysis
	for _, m := range a.Members {
		if needsReview(m, knownGood) {
			result = append(result, m)
		}
	}
	return result
}

// jsonlEntry represents a single JSONL line from streaming output.
type jsonlEntry struct {
	Type          string    `json:"type"`
	Path          string    `json:"path"`
	FileType      string    `json:"file_type"`
	Risk          string    `json:"risk"`
	ExtractedPath string    `json:"extracted_path,omitempty"`
	Findings      []Finding `json:"findings"`
}

func main() {
	log.SetFlags(0)

	dir := flag.String("dir", "", "Directory to scan recursively (required)")
	knownGood := flag.Bool("good", false, "Review known-good files for false positives (suspicious/hostile findings)")
	knownBad := flag.Bool("bad", false, "Review known-bad files for false negatives (missing detections)")
	provider := flag.String("provider", "claude", "AI provider: claude, gemini, or opencode")
	model := flag.String("model", "", `Model to use (provider-specific). Popular choices:
  claude:   sonnet, opus, haiku
  gemini:   gemini-3-pro-preview, gemini-3-flash-preview,
            gemini-2.5-pro, gemini-2.5-flash, gemini-2.5-flash-lite
  opencode: gpt-4.1, gpt-4.1-mini, o4-mini, o3, moonshotai/kimi-k2.5`)
	repoRoot := flag.String("repo-root", "", "Path to DISSECT repo root (auto-detected if not specified)")
	useCargo := flag.Bool("cargo", true, "Use 'cargo run --release' instead of dissect binary")
	timeout := flag.Duration("timeout", 20*time.Minute, "Maximum time for each AI invocation")
	flush := flag.Bool("flush", false, "Clear analysis cache and reprocess all files")

	flag.Parse()

	if *dir == "" {
		log.Fatal("--dir is required")
	}
	if info, err := os.Stat(*dir); err != nil {
		if os.IsNotExist(err) {
			log.Fatalf("Directory does not exist: %s", *dir)
		}
		log.Fatalf("Cannot access directory %s: %v", *dir, err)
	} else if !info.IsDir() {
		log.Fatalf("Not a directory: %s", *dir)
	}
	if !*knownGood && !*knownBad {
		log.Fatal("Either --good or --bad is required")
	}
	if *knownGood && *knownBad {
		log.Fatal("Cannot specify both --good and --bad")
	}

	*provider = strings.ToLower(*provider)
	if *provider != "claude" && *provider != "gemini" && *provider != "opencode" {
		log.Fatalf("Unknown provider %q: must be claude, gemini, or opencode", *provider)
	}

	// Find repo root (for running dissect via cargo).
	resolvedRoot := *repoRoot
	if resolvedRoot == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
		cancel()
		if err != nil {
			log.Fatalf("Could not detect repo root: %v. Use --repo-root flag.", err)
		}
		resolvedRoot = strings.TrimSpace(string(out))
	}

	db, err := openDB(context.Background(), *flush)
	if err != nil {
		log.Fatalf("Could not open database: %v", err)
	}

	// Create temp directory for extracted samples (for LLM to use radare2, etc.).
	sampleDir, err := os.MkdirTemp("", "trait-basher-samples-*")
	if err != nil {
		db.Close() //nolint:errcheck,gosec // best-effort cleanup on fatal error
		log.Fatalf("Could not create sample directory: %v", err)
	}
	defer func() { os.RemoveAll(sampleDir) }() //nolint:errcheck,gosec // best-effort cleanup
	defer func() { db.Close() }()              //nolint:errcheck,gosec // best-effort cleanup

	cfg := &config{
		dir:       *dir,
		repoRoot:  resolvedRoot,
		provider:  *provider,
		model:     *model,
		timeout:   *timeout,
		knownGood: *knownGood,
		knownBad:  *knownBad,
		useCargo:  *useCargo,
		flush:     *flush,
		db:        db,
		sampleDir: sampleDir,
	}

	ctx := context.Background()

	// Sanity check: run dissect on /bin/ls to catch code errors early.
	if err := sanityCheck(ctx, cfg); err != nil {
		//nolint:gocritic // exitAfterDefer: defers won't run after log.Fatalf, acceptable for fatal errors
		log.Fatalf("Sanity check failed: %v", err)
	}

	mode := "known-bad"
	if cfg.knownGood {
		mode = "known-good"
	}

	if cfg.model != "" {
		fmt.Fprintf(os.Stderr, "Provider: %s (model: %s)\n", cfg.provider, cfg.model)
	} else {
		fmt.Fprintf(os.Stderr, "Provider: %s\n", cfg.provider)
	}
	fmt.Fprintf(os.Stderr, "Mode: %s\n", mode)
	fmt.Fprintf(os.Stderr, "Repo root: %s\n", cfg.repoRoot)
	fmt.Fprintf(os.Stderr, "Streaming analysis of %s...\n\n", cfg.dir)

	// Database mode (good/bad, not known-good/known-bad).
	dbMode := "bad"
	if cfg.knownGood {
		dbMode = "good"
	}

	// Use streaming analysis - process each archive as it completes.
	stats, err := streamAnalyzeAndReview(ctx, cfg, dbMode)
	if err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}

	fmt.Fprintf(os.Stderr, "\nDone. Reviewed %d archives, %d standalone files. Skipped %d (cached), %d (no review needed).\n",
		stats.archivesReviewed, stats.standaloneReviewed, stats.skippedCached, stats.skippedNoReview)
	fmt.Fprint(os.Stderr, "Run \"git diff traits/\" to see changes.\n")
}

// streamStats tracks streaming analysis statistics.
type streamStats struct {
	archivesReviewed   int
	standaloneReviewed int
	skippedCached      int
	skippedNoReview    int
	totalFiles         int
}

// streamState tracks the current processing state as we stream files.
type streamState struct {
	cfg                *config
	dbMode             string
	stats              *streamStats
	currentArchive     *ArchiveAnalysis
	currentArchivePath string
	currentRealFile    *RealFileAnalysis
	currentRealPath    string
}

// streamAnalyzeAndReview streams dissect output and reviews archives as they complete.
func streamAnalyzeAndReview(ctx context.Context, cfg *config, dbMode string) (*streamStats, error) {
	cmd := buildDissectCommand(ctx, cfg)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("could not create stdout pipe: %w", err)
	}

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start dissect: %w", err)
	}

	state := &streamState{
		cfg:    cfg,
		dbMode: dbMode,
		stats:  &streamStats{},
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 128*1024*1024), 128*1024*1024) // 128MB buffer

	fileCount := 0
	lastProgress := time.Now()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry jsonlEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if entry.Type != "file" {
			continue
		}

		fileCount++

		if time.Since(lastProgress) > 100*time.Millisecond {
			fmt.Fprintf(os.Stderr, "\r  Scanning... %d files processed", fileCount)
			lastProgress = time.Now()
		}

		f := FileAnalysis{
			Path:          entry.Path,
			Risk:          entry.Risk,
			Findings:      entry.Findings,
			ExtractedPath: entry.ExtractedPath,
		}

		archivePath := rootArchive(f.Path)
		processFileEntry(ctx, state, f, archivePath)
	}

	if state.currentRealFile != nil {
		clearProgressLine()
		processRealFile(ctx, state)
	}
	if state.currentArchive != nil {
		clearProgressLine()
		processCompletedArchive(ctx, state)
	}

	if err := scanner.Err(); err != nil {
		return state.stats, fmt.Errorf("error reading dissect output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		if msg := strings.TrimSpace(stderrBuf.String()); msg != "" {
			return state.stats, fmt.Errorf("dissect error: %s", msg)
		}
		return state.stats, fmt.Errorf("dissect failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\r  Scanned %d files total                    \n", fileCount)
	return state.stats, nil
}

func buildDissectCommand(ctx context.Context, cfg *config) *exec.Cmd {
	sampleMaxRisk := "notable"
	if cfg.knownGood {
		sampleMaxRisk = "hostile"
	}

	var cmd *exec.Cmd
	if cfg.useCargo {
		args := []string{
			"run", "--release", "--",
			"--format", "jsonl",
			"--sample-dir", cfg.sampleDir,
			"--sample-max-risk", sampleMaxRisk,
			cfg.dir,
		}
		cmd = exec.CommandContext(ctx, "cargo", args...)
		cmd.Dir = cfg.repoRoot
	} else {
		args := []string{
			"--format", "jsonl",
			"--sample-dir", cfg.sampleDir,
			"--sample-max-risk", sampleMaxRisk,
			cfg.dir,
		}
		cmd = exec.CommandContext(ctx, "dissect", args...)
	}
	return cmd
}

func clearProgressLine() {
	fmt.Fprint(os.Stderr, "\r                                        \r")
}

func processFileEntry(ctx context.Context, state *streamState, f FileAnalysis, archivePath string) {
	switch {
	case archivePath == "":
		// Standalone file (not in an archive)
		if state.currentArchive != nil {
			clearProgressLine()
			processCompletedArchive(ctx, state)
			state.currentArchive = nil
			state.currentArchivePath = ""
		}

		// Check if this is a fragment or root file
		fPath := realFilePath(f.Path)
		if fPath == state.currentRealPath && state.currentRealFile != nil {
			// Same real file: add as fragment
			state.currentRealFile.Fragments = append(state.currentRealFile.Fragments, f)
			return
		}

		// Different real file: process previous and start new
		if state.currentRealFile != nil {
			clearProgressLine()
			processRealFile(ctx, state)
			state.currentRealFile = nil
			state.currentRealPath = ""
		}

		// Start new real file
		newReal := &RealFileAnalysis{
			RealPath:  fPath,
			Fragments: []FileAnalysis{},
		}
		if isFragment(f.Path) {
			// This entry itself is a fragment; root file entry may come later
			newReal.Fragments = []FileAnalysis{f}
		} else {
			// This is the root file entry
			newReal.Root = f
		}
		state.currentRealFile = newReal
		state.currentRealPath = fPath

	case archivePath != state.currentArchivePath:
		// Different archive: process everything pending
		if state.currentArchive != nil {
			clearProgressLine()
			processCompletedArchive(ctx, state)
		}
		if state.currentRealFile != nil {
			clearProgressLine()
			processRealFile(ctx, state)
			state.currentRealFile = nil
			state.currentRealPath = ""
		}
		state.currentArchive = &ArchiveAnalysis{
			ArchivePath: archivePath,
			Members:     []FileAnalysis{f},
		}
		state.currentArchivePath = archivePath

	default:
		// Same archive: just add to current archive members
		state.currentArchive.Members = append(state.currentArchive.Members, f)
	}
}

func processCompletedArchive(ctx context.Context, state *streamState) {
	archive := state.currentArchive
	if archive == nil || len(archive.Members) == 0 {
		return
	}

	state.stats.totalFiles += len(archive.Members)

	if !archiveNeedsReview(archive, state.cfg.knownGood) {
		state.stats.skippedNoReview++
		return
	}

	h := hashString(archive.ArchivePath)
	if wasAnalyzed(ctx, state.cfg.db, h, state.dbMode) {
		state.stats.skippedCached++
		return
	}

	problematic := archiveProblematicMembers(archive, state.cfg.knownGood)
	fmt.Fprintf(os.Stderr, "\n📦 Archive complete: %s\n", archive.ArchivePath)
	fmt.Fprintf(os.Stderr, "   Members: %d total, %d need review\n", len(archive.Members), len(problematic))

	rank := map[string]int{"inert": 0, "notable": 1, "suspicious": 2, "hostile": 3}
	for i, m := range problematic {
		if i >= 3 {
			fmt.Fprintf(os.Stderr, "   ... and %d more\n", len(problematic)-3)
			break
		}
		var maxCrit string
		for _, f := range m.Findings {
			if rank[strings.ToLower(f.Crit)] > rank[strings.ToLower(maxCrit)] {
				maxCrit = f.Crit
			}
		}
		fmt.Fprintf(os.Stderr, "   - %s (%s)\n", memberPath(m.Path), maxCrit)
	}

	sid := generateSessionID()
	if err := invokeAIArchive(ctx, state.cfg, archive, sid); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %s failed for %s: %v\n", state.cfg.provider, archive.ArchivePath, err)
	} else {
		if err := markAnalyzed(ctx, state.cfg.db, h, state.dbMode); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not record analysis for %s: %v\n", archive.ArchivePath, err)
		}
		state.stats.archivesReviewed++
	}
}

func processRealFile(ctx context.Context, state *streamState) {
	rf := state.currentRealFile
	if rf == nil || rf.RealPath == "" {
		return
	}

	state.stats.totalFiles++

	if !realFileNeedsReview(rf, state.cfg.knownGood) {
		state.stats.skippedNoReview++
		return
	}

	h, err := hashFile(rf.RealPath)
	if err != nil {
		h = hashString(rf.RealPath)
	}
	if wasAnalyzed(ctx, state.cfg.db, h, state.dbMode) {
		state.stats.skippedCached++
		return
	}

	// Aggregate findings from root and all fragments
	aggregated := rf.Root
	if aggregated.Path == "" {
		// No root file entry was seen, use the real path
		aggregated.Path = rf.RealPath
	}
	for _, frag := range rf.Fragments {
		aggregated.Findings = append(aggregated.Findings, frag.Findings...)
	}

	fmt.Fprintf(os.Stderr, "\n📄 Standalone file: %s\n", rf.RealPath)
	if len(rf.Fragments) > 0 {
		fmt.Fprintf(os.Stderr, "   (with %d decoded fragment(s))\n", len(rf.Fragments))
	}

	rank := map[string]int{"inert": 0, "notable": 1, "suspicious": 2, "hostile": 3}
	var maxCrit string
	for _, f := range aggregated.Findings {
		if rank[strings.ToLower(f.Crit)] > rank[strings.ToLower(maxCrit)] {
			maxCrit = f.Crit
		}
	}
	if maxCrit != "" {
		fmt.Fprintf(os.Stderr, "   Risk: %s, Findings: %d\n", maxCrit, len(aggregated.Findings))
	}

	sid := generateSessionID()
	if err := invokeAI(ctx, state.cfg, aggregated, sid); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %s failed for %s: %v\n", state.cfg.provider, rf.RealPath, err)
	} else {
		if err := markAnalyzed(ctx, state.cfg.db, h, state.dbMode); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not record analysis for %s: %v\n", rf.RealPath, err)
		}
		state.stats.standaloneReviewed++
	}
}

// needsReview determines if a file needs AI review based on mode.
// --good: Review files WITH suspicious/hostile findings (reduce false positives).
// --bad: Review files WITHOUT suspicious/hostile findings (find false negatives).
func needsReview(f FileAnalysis, knownGood bool) bool {
	for _, finding := range f.Findings {
		c := strings.ToLower(finding.Crit)
		if c == "suspicious" || c == "hostile" {
			return knownGood // Has suspicious: review if --good (FP check)
		}
	}
	return !knownGood // No suspicious: review if --bad (FN check)
}

// realFileNeedsReview determines if a real file (with all its fragments) needs review.
func realFileNeedsReview(rf *RealFileAnalysis, knownGood bool) bool {
	// Check root file
	if needsReview(rf.Root, knownGood) {
		return true
	}
	// Check any fragment
	for _, frag := range rf.Fragments {
		if needsReview(frag, knownGood) {
			return true
		}
	}
	return false
}

// sanityCheck runs dissect on /bin/ls to catch code errors early.
func sanityCheck(ctx context.Context, cfg *config) error {
	const testFile = "/bin/ls"
	fmt.Fprintf(os.Stderr, "Sanity check: running dissect on %s...\n", testFile)

	var cmd *exec.Cmd
	if cfg.useCargo {
		cmd = exec.CommandContext(ctx, "cargo", "run", "--release", "--", "--format", "jsonl", testFile)
		cmd.Dir = cfg.repoRoot
	} else {
		cmd = exec.CommandContext(ctx, "dissect", "--format", "jsonl", testFile)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprint(os.Stderr, "\n=== SANITY CHECK FAILED ===\n")
		if stderr.Len() > 0 {
			fmt.Fprintf(os.Stderr, "stderr:\n%s\n", stderr.String())
		}
		if stdout.Len() > 0 {
			fmt.Fprintf(os.Stderr, "stdout:\n%s\n", stdout.String())
		}
		return fmt.Errorf("dissect failed on %s: %w", testFile, err)
	}

	fmt.Fprint(os.Stderr, "Sanity check passed.\n\n")
	return nil
}

func invokeAI(ctx context.Context, cfg *config, f FileAnalysis, sid string) error {
	var prompt, task string
	if cfg.knownGood {
		prompt = fmt.Sprintf(knownGoodPrompt, f.Path, f.Path, cfg.repoRoot)
		task = "Review for false positives (known-good collection)"
	} else {
		prompt = fmt.Sprintf(knownBadPrompt, f.Path, f.Path, cfg.repoRoot)
		task = "Find missing detections (known-bad collection)"
	}

	if f.ExtractedPath != "" {
		prompt += fmt.Sprintf("\n\n## Extracted Sample\nThe file has been extracted to: %s\n"+
			"Use this path for binary analysis tools (radare2, strings, objdump, xxd, nm).", f.ExtractedPath)
	}

	critCounts := make(map[string]int)
	for _, finding := range f.Findings {
		critCounts[strings.ToLower(finding.Crit)]++
	}
	var critSummary []string
	for _, level := range []string{"hostile", "suspicious", "notable", "inert"} {
		if n := critCounts[level]; n > 0 {
			critSummary = append(critSummary, fmt.Sprintf("%d %s", n, level))
		}
	}

	fmt.Fprintln(os.Stderr, "┌─────────────────────────────────────────────────────────────")
	fmt.Fprintf(os.Stderr, "│ %s REVIEW: %s\n", strings.ToUpper(cfg.provider), f.Path)
	fmt.Fprintf(os.Stderr, "│ Findings: %s\n", strings.Join(critSummary, ", "))
	if f.ExtractedPath != "" {
		fmt.Fprintf(os.Stderr, "│ Sample: %s\n", f.ExtractedPath)
	}
	fmt.Fprintf(os.Stderr, "│ Task: %s\n", task)
	fmt.Fprintln(os.Stderr, "├─────────────────────────────────────────────────────────────")
	fmt.Fprintln(os.Stderr, "│ Prompt (abbreviated):")
	var promptLines []string
	for line := range strings.SplitSeq(prompt, "\n") {
		promptLines = append(promptLines, line)
	}
	for i, line := range promptLines {
		if i < 20 || i >= len(promptLines)-5 {
			fmt.Fprintf(os.Stderr, "│   %s\n", line)
		} else if i == 20 {
			fmt.Fprintf(os.Stderr, "│   ... (%d lines of findings JSON) ...\n", len(promptLines)-25)
		}
	}
	fmt.Fprintln(os.Stderr, "└─────────────────────────────────────────────────────────────")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, ">>> %s working (timeout: %s)...\n", cfg.provider, cfg.timeout)
	fmt.Fprintln(os.Stderr)

	timedCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	if err := runAIWithStreaming(timedCtx, cfg, prompt, sid); err != nil {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "<<< %s failed: %v\n", cfg.provider, err)
		return err
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "<<< %s finished\n", cfg.provider)
	return nil
}

func invokeAIArchive(ctx context.Context, cfg *config, a *ArchiveAnalysis, sid string) error {
	problematic := archiveProblematicMembers(a, cfg.knownGood)

	// Extract archive (full for --bad, problematic files only for --good)
	extractDir, err := os.MkdirTemp("", "trait-basher-archive-*")
	if err != nil {
		return fmt.Errorf("create extract directory: %w", err)
	}
	defer os.RemoveAll(extractDir) //nolint:errcheck,gosec

	var extractedInfo string

	if cfg.knownBad {
		// --bad mode: extract full archive for comprehensive analysis
		_, err = extractArchive(ctx, a.ArchivePath, extractDir)
		if err != nil {
			return fmt.Errorf("extract archive: %w", err)
		}

		// Find stats for hints
		mostNotable, largest := archiveMemberStats(a)
		var hints []string
		if mostNotable != nil {
			hints = append(hints, fmt.Sprintf("Most notable findings in: %s", memberPath(mostNotable.Path)))
		}
		if largest != nil {
			hints = append(hints, fmt.Sprintf("Largest file: %s", memberPath(largest.Path)))
		}

		extractedInfo = fmt.Sprintf("\n\n## Extracted Archive\nFull archive extracted to: %s\n"+
			"You can now read the actual source code to understand the malicious behavior.\n",
			extractDir)
		if len(hints) > 0 {
			extractedInfo += "Hints for investigation:\n"
			for _, h := range hints {
				extractedInfo += fmt.Sprintf("- %s\n", h)
			}
		}
		extractedInfo += "After analyzing, update the rules in traits/ to detect the malicious behavior found."
	} else {
		// --good mode: extract only problematic files
		extractDir2, err := os.MkdirTemp("", "trait-basher-problematic-*")
		if err != nil {
			return fmt.Errorf("create problematic extract directory: %w", err)
		}
		defer os.RemoveAll(extractDir2) //nolint:errcheck,gosec

		for _, m := range problematic {
			if m.ExtractedPath != "" {
				base := filepath.Base(m.Path)
				dstPath := filepath.Join(extractDir2, base)
				if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
					return fmt.Errorf("create directory: %w", err)
				}
				src, err := os.Open(m.ExtractedPath)
				if err != nil {
					return fmt.Errorf("open extracted file %s: %w", m.ExtractedPath, err)
				}
				dst, err := os.Create(dstPath)
				if err != nil {
					src.Close() //nolint:errcheck
					return fmt.Errorf("create destination file: %w", err)
				}
				if _, err := io.Copy(dst, src); err != nil {
					src.Close()  //nolint:errcheck
					dst.Close() //nolint:errcheck
					return fmt.Errorf("copy extracted file: %w", err)
				}
				src.Close()  //nolint:errcheck
				dst.Close() //nolint:errcheck
			}
		}

		extractedInfo = fmt.Sprintf("\n\n## Problematic Files\nFalse positive files extracted to: %s\n"+
			"Review these files to understand why they're being incorrectly flagged.\n"+
			"Adjust the rules in traits/ to fix the false positives.",
			extractDir2)
	}

	var prompt, task string
	if cfg.knownGood {
		prompt = fmt.Sprintf(knownGoodArchivePrompt, a.ArchivePath, len(problematic), a.ArchivePath, cfg.repoRoot)
		task = "Review archive for false positives (known-good collection)"
	} else {
		prompt = fmt.Sprintf(knownBadArchivePrompt, a.ArchivePath, len(problematic), a.ArchivePath, cfg.repoRoot)
		task = "Find missing detections in archive (known-bad collection)"
	}

	prompt += extractedInfo

	// Still include extracted binary samples if available
	if cfg.knownGood && len(problematic) > 0 {
		var extractedPaths []string
		for _, m := range problematic {
			if m.ExtractedPath != "" {
				extractedPaths = append(extractedPaths, fmt.Sprintf("- %s", m.ExtractedPath))
			}
		}
		if len(extractedPaths) > 0 {
			prompt += fmt.Sprintf("\nBinary analysis tools available at: %s\n%s",
				cfg.sampleDir, strings.Join(extractedPaths, "\n"))
		}
	}

	critCounts := make(map[string]int)
	for _, m := range a.Members {
		for _, finding := range m.Findings {
			critCounts[strings.ToLower(finding.Crit)]++
		}
	}
	var critSummary []string
	for _, level := range []string{"hostile", "suspicious", "notable", "inert"} {
		if n := critCounts[level]; n > 0 {
			critSummary = append(critSummary, fmt.Sprintf("%d %s", n, level))
		}
	}

	fmt.Fprintln(os.Stderr, "┌─────────────────────────────────────────────────────────────")
	fmt.Fprintf(os.Stderr, "│ %s ARCHIVE REVIEW: %s\n", strings.ToUpper(cfg.provider), a.ArchivePath)
	fmt.Fprintf(os.Stderr, "│ Members: %d total, %d problematic\n", len(a.Members), len(problematic))
	fmt.Fprintf(os.Stderr, "│ Findings: %s\n", strings.Join(critSummary, ", "))
	fmt.Fprintf(os.Stderr, "│ Task: %s\n", task)
	fmt.Fprintln(os.Stderr, "├─────────────────────────────────────────────────────────────")
	fmt.Fprintln(os.Stderr, "│ Prompt (abbreviated):")
	var promptLines []string
	for line := range strings.SplitSeq(prompt, "\n") {
		promptLines = append(promptLines, line)
	}
	for i, line := range promptLines {
		if i < 30 || i >= len(promptLines)-5 {
			fmt.Fprintf(os.Stderr, "│   %s\n", line)
		} else if i == 30 {
			fmt.Fprintf(os.Stderr, "│   ... (%d lines) ...\n", len(promptLines)-35)
		}
	}
	fmt.Fprintln(os.Stderr, "└─────────────────────────────────────────────────────────────")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, ">>> %s working (timeout: %s)...\n", cfg.provider, cfg.timeout)
	fmt.Fprintln(os.Stderr)

	timedCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	err = runAIWithStreaming(timedCtx, cfg, prompt, sid)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "<<< %s failed: %v\n", cfg.provider, err)
		return err
	}
	fmt.Fprintf(os.Stderr, "<<< %s finished\n", cfg.provider)
	return nil
}

func runAIWithStreaming(ctx context.Context, cfg *config, prompt, sid string) error {
	var cmd *exec.Cmd

	switch cfg.provider {
	case "claude":
		args := []string{
			"-p", prompt,
			"--verbose",
			"--output-format", "stream-json",
			"--dangerously-skip-permissions",
			"--session-id", sid,
		}
		if cfg.model != "" {
			args = append(args, "--model", cfg.model)
		}
		cmd = exec.CommandContext(ctx, "claude", args...)
	case "gemini":
		args := []string{
			"-p", prompt,
			"--yolo",
			"--output-format", "stream-json",
		}
		if cfg.model != "" {
			args = append(args, "--model", cfg.model)
		}
		cmd = exec.CommandContext(ctx, "gemini", args...)
	case "opencode":
		args := []string{"-p", prompt}
		if cfg.model != "" {
			args = append(args, "--model", cfg.model)
		}
		cmd = exec.CommandContext(ctx, "opencode", args...)
	default:
		return fmt.Errorf("unknown provider: %s", cfg.provider)
	}

	cmd.Dir = cfg.repoRoot

	if devNull, err := os.Open(os.DevNull); err == nil {
		cmd.Stdin = devNull
		defer func() { devNull.Close() }() //nolint:errcheck,gosec // best-effort cleanup
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("could not create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("could not create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start %s: %w", cfg.provider, err)
	}

	var stderrLines []string
	var stderrMu sync.Mutex
	done := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			displayStreamEvent(scanner.Text())
		}
		done <- struct{}{}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintf(os.Stderr, "  [stderr] %s\n", line)
			stderrMu.Lock()
			stderrLines = append(stderrLines, line)
			stderrMu.Unlock()
		}
		done <- struct{}{}
	}()

	finished := 0
	for finished < 2 {
		select {
		case <-done:
			finished++
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "\n  [timeout] timed out, killing process...")
			io.Copy(io.Discard, stdout) //nolint:errcheck,gosec // drain pipes on timeout
			io.Copy(io.Discard, stderr) //nolint:errcheck,gosec // drain pipes on timeout
			cmd.Process.Kill()          //nolint:errcheck,gosec // best-effort kill on timeout
			return fmt.Errorf("timeout: %w", ctx.Err())
		}
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errors.New("exceeded time limit")
		}
		stderrMu.Lock()
		lastLines := stderrLines
		if len(lastLines) > 5 {
			lastLines = lastLines[len(lastLines)-5:]
		}
		stderrMu.Unlock()
		if len(lastLines) > 0 {
			return fmt.Errorf("%s exited with error: %w\nLast stderr output:\n  %s",
				cfg.provider, err, strings.Join(lastLines, "\n  "))
		}
		return fmt.Errorf("%s exited with error: %w", cfg.provider, err)
	}
	return nil
}

// displayStreamEvent parses a stream-json line and displays relevant info.
func displayStreamEvent(line string) {
	var ev map[string]any
	if json.Unmarshal([]byte(line), &ev) != nil {
		return
	}
	switch ev["type"] {
	case "assistant":
		displayAssistantEvent(ev)
	case "result":
		displayResultEvent(ev)
	default:
	}
}

func displayAssistantEvent(ev map[string]any) {
	msg, ok := ev["message"].(map[string]any)
	if !ok {
		return
	}
	content, ok := msg["content"].([]any)
	if !ok {
		return
	}
	for _, c := range content {
		b, ok := c.(map[string]any)
		if !ok {
			continue
		}
		switch b["type"] {
		case "tool_use":
			displayToolUse(b)
		case "text":
			if t, ok := b["text"].(string); ok && t != "" {
				fmt.Fprintf(os.Stderr, "  %s\n", t)
			}
		default:
		}
	}
}

func displayToolUse(b map[string]any) {
	name, ok := b["name"].(string)
	if !ok || name == "" {
		name = "unknown"
	}
	input, ok := b["input"].(map[string]any)
	if !ok {
		fmt.Fprintf(os.Stderr, "  [tool] %s\n", name)
		return
	}
	var detail string
	for _, k := range []string{"description", "command", "pattern", "file_path"} {
		if v, ok := input[k].(string); ok {
			detail = v
			break
		}
	}
	if len(detail) > 80 {
		detail = detail[:80] + "..."
	}
	if detail != "" {
		fmt.Fprintf(os.Stderr, "  [tool] %s: %s\n", name, detail)
	} else {
		fmt.Fprintf(os.Stderr, "  [tool] %s\n", name)
	}
}

func displayResultEvent(ev map[string]any) {
	if r, ok := ev["result"].(string); ok && r != "" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "--- Result ---")
		fmt.Fprintln(os.Stderr, r)
	}
	if cost, ok := ev["total_cost_usd"].(float64); ok {
		fmt.Fprintf(os.Stderr, "\n  Cost: $%.4f\n", cost)
	}
}

func generateSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		ts := time.Now().UnixNano()
		return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			ts>>32, (ts>>16)&0xffff, ts&0xffff, 0x4000, ts&0xffffffffffff)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Database functions for tracking analyzed files.

func configDir() (string, error) {
	var base string
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, "Library", "Application Support")
	default:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			base = xdg
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".config")
		}
	}
	return filepath.Join(base, "dissect"), nil
}

func openDB(ctx context.Context, flush bool) (*sql.DB, error) {
	dir, err := configDir()
	if err != nil {
		return nil, fmt.Errorf("config directory: %w", err)
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create config directory: %w", err)
	}

	dbPath := filepath.Join(dir, "trait-basher.db")

	if flush {
		if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("remove database: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Flushed analysis cache: %s\n", dbPath)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS analyzed_files (
			file_hash TEXT NOT NULL,
			mode TEXT NOT NULL,
			analyzed_at INTEGER NOT NULL,
			PRIMARY KEY (file_hash, mode)
		)
	`)
	if err != nil {
		db.Close() //nolint:errcheck,gosec // best-effort cleanup on error
		return nil, fmt.Errorf("create table: %w", err)
	}

	return db, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { f.Close() }() //nolint:errcheck,gosec // best-effort cleanup

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashString returns SHA256 hash of a string (for archive path caching).
func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func wasAnalyzed(ctx context.Context, db *sql.DB, hash, mode string) bool {
	var n int
	err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM analyzed_files WHERE file_hash = ? AND mode = ?",
		hash, mode,
	).Scan(&n)
	return err == nil && n > 0
}

func markAnalyzed(ctx context.Context, db *sql.DB, hash, mode string) error {
	_, err := db.ExecContext(ctx,
		"INSERT OR REPLACE INTO analyzed_files (file_hash, mode, analyzed_at) VALUES (?, ?, ?)",
		hash, mode, time.Now().Unix(),
	)
	return err
}
