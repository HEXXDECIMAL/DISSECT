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

// Shared prompt building blocks (LLM-optimized)

const keyConstraints = `## Key Constraints (Do Not Violate)
- **Read documentation**: Check RULES.md and TAXONOMY.md to understand naming conventions and design principles
- **YAML is valid**: DISSECT's strict parser already validated it. Only edit trait logic, not formatting.
- **Preserve structure**: Keep indentation, spacing, and file organization identical.
- **No new files**: Only modify existing traits/ YAML files.
- **One fix per trait**: Don't over-engineer; each trait should do one thing well.`

const successCriteria = `## Success Criteria
✓ All false positive findings are fixed (incorrect matches removed or constrained)
✓ Remaining findings accurately describe what the program actually does
✓ No new false positives introduced
✓ Changes are minimal and focused (3-5 edits max)
✓ Run dissect again - shows improvement`

const debugCommands = `## Debug & Validate
` + "```" + `
%s %s --format jsonl                   # see current findings
%s test-rules %s --rules "rule-id"     # debug single rule
%s test-match %s --type string --pattern "X"  # test patterns
` + "```" + ``

const falsePositiveDefinition = `## What Is a False Positive?
A **false positive** is a finding that DOES NOT match what the program actually does.
- If the program DOES execute code → "exec" finding is CORRECT, not a false positive
- If the program DOES read files → "file_read" finding is CORRECT, not a false positive
- If the program DOES open sockets → "socket" finding is CORRECT, not a false positive

A finding is only a false positive if:
- The rule incorrectly matched something that doesn't indicate that behavior
- The pattern is too broad and matches unrelated benign code
- The finding is in the wrong file or context

**Expected**: Known-good software has findings! Notable and suspicious findings are normal if they accurately describe what the code does. The goal is ACCURATE findings, not zero findings.`

const goodPromptTask = `## Strategy: Fix False Positives
Review findings and identify which are actually false positives (incorrect matches).
Keep findings that accurately describe the code's behavior, even if suspicious.

**Priority Order** (try in this order):
1. **Taxonomy**: Trait in wrong directory? Move it (e.g., cap/ not obj/)
2. **Patterns**: Too broad? Refine the pattern itself to be more accurate:
   - ` + "`near: 200`" + ` - require proximity to suspicious code
   - ` + "`size_min/max`" + ` - filter by file size (legitimate: large, malware: compact)
   - ` + "`for: [elf, macho, pe]`" + ` - restrict to binaries (skip scripts)
   - ` + "`all:`" + ` in composites - combine weak signals into strong one
3. **Exclusions**: Too specific? Add ` + "`not:`" + ` filters to exclude known-good patterns
4. **Reorganize**: Create new traits if it makes the logic clearer or more maintainable
5. **Exceptions** (last resort): Only use ` + "`unless:`" + ` or ` + "`downgrade:`" + ` if fixing the pattern is impractical

**Prefer**: Fixing queries to be accurate over adding exceptions. A well-tuned pattern is better than a broad pattern with exceptions.

**If deleting or renaming a trait**: Update all references to it (in composites, depends, etc.). Consider what the composite trait was trying to accomplish and fix the reference appropriately.

**Do Not**: Change criticality levels arbitrarily, remove accurate findings, or break YAML structure.`

const goodPromptArchiveTask = `## Strategy: Fix False Positives in Archive
Review findings and identify which are actually false positives (incorrect matches).
Keep findings that accurately describe the code's behavior, even if suspicious.

**Priority Order** (try in this order):
1. **Taxonomy**: Trait in wrong directory? Move it (e.g., cap/ not obj/)
2. **Patterns**: Too broad? Refine the pattern itself to be more accurate:
   - ` + "`near: 200`" + ` - require proximity to suspicious code
   - ` + "`size_min/max`" + ` - legitimate installers are huge, malware is compact
   - ` + "`for: [elf, macho, pe]`" + ` - restrict to binaries only
   - ` + "`all:`" + ` in composites - combine weak signals, don't flag individually
3. **Exclusions**: Known-good strings? Add ` + "`not:`" + ` filters to exclude them
4. **Reorganize**: Create new traits if it makes the logic clearer or more maintainable
5. **Exceptions** (last resort): Only use ` + "`unless:`" + ` or ` + "`downgrade:`" + ` if fixing the pattern is impractical

**Prefer**: Fixing queries to be accurate over adding exceptions. A well-tuned pattern is better than a broad pattern with exceptions.

**If deleting or renaming a trait**: Update all references to it (in composites, depends, etc.). Consider what the composite trait was trying to accomplish and fix the reference appropriately.

**Do Not**: Change criticality levels arbitrarily, remove accurate findings, or break YAML structure.`

const badPromptTask = `## Strategy: Add Missing Detection
**Approach**:
1. Reverse engineer the file (strings, radare2, nm, objdump)
2. Identify malicious capability (socket + exec = reverse-shell, etc.)
3. Use GENERIC patterns, not file-specific signatures
4. Trait namespaces:
   - cap/X = neutral capability (socket, exec, file ops) - could be benign
   - obj/X = attacker objective (combine multiple caps) - clearly malicious
   - known/ = ONLY for named malware families (apt/cozy-bear, trojan/emotet)
5. Cross-language when possible (base64+exec works in Python, JS, Shell)
6. Create new traits if needed - they should be generic and reusable across samples

**If deleting or renaming a trait**: Update all references to it (in composites, depends, etc.). Consider what the composite trait was trying to accomplish and fix the reference appropriately.

**Do Not**: Create file-specific rules, add unrelated traits, or ignore YAML structure.`

const badPromptArchiveTask = `## Strategy: Add Missing Detection to Archive
**Approach**:
1. For each problematic member: reverse engineer (strings, radare2, nm, objdump)
2. Identify malicious capability (socket + exec = reverse-shell, etc.)
3. Use GENERIC patterns, not file-specific signatures
4. Trait namespaces:
   - cap/X = neutral capability (socket, exec, file ops) - could be benign
   - obj/X = attacker objective (combine multiple caps) - clearly malicious
   - known/ = ONLY for named malware families (apt/cozy-bear, trojan/emotet)
5. Cross-language patterns when possible (base64+exec in Python, JS, Shell)
6. Create new traits if needed - they should be generic and reusable across samples

**If deleting or renaming a trait**: Update all references to it (in composites, depends, etc.). Consider what the composite trait was trying to accomplish and fix the reference appropriately.

**Do Not**: Create file-specific rules, add unrelated traits, or break YAML format.`

// Helper function to build prompts from blocks
func buildGoodPrompt(isArchive bool, path string, archiveCount int, repoRoot, dissectBin string) string {
	var header string
	var taskBlock string
	var debugCmd string

	if isArchive {
		header = fmt.Sprintf("# Fix False Positives in KNOWN-GOOD Archive\n\n**Archive**: %s\n**Problem**: %d members flagged as suspicious/hostile\n**Task**: Remove false positive findings\n", path, archiveCount)
		taskBlock = goodPromptArchiveTask
		debugCmd = path
	} else {
		header = fmt.Sprintf("# Fix False Positives in KNOWN-GOOD File\n\n**File**: %s\n**Problem**: Flagged as suspicious/hostile\n**Task**: Remove false positive findings\n", path)
		taskBlock = goodPromptTask
		debugCmd = path
	}

	debug := fmt.Sprintf(debugCommands, dissectBin, debugCmd, dissectBin, debugCmd, dissectBin, debugCmd)

	return fmt.Sprintf("%s\n%s\n\n%s\n\n%s\n\n%s\n\n%s\n\nTraits: %s/traits/", header, falsePositiveDefinition, keyConstraints, taskBlock, successCriteria, debug, repoRoot)
}

func buildBadPrompt(isArchive bool, path string, archiveCount int, repoRoot, dissectBin string) string {
	var header string
	var taskBlock string
	var debugCmd string

	if isArchive {
		header = fmt.Sprintf("# Add Missing Detection for KNOWN-BAD Archive\n\n**Archive**: %s\n**Problem**: %d members not flagged as suspicious/hostile\n**Task**: Detect malicious behavior\n\n*Note: Skip genuinely benign files (README, docs, unmodified dependencies)*\n", path, archiveCount)
		taskBlock = badPromptArchiveTask
		debugCmd = path
	} else {
		header = fmt.Sprintf("# Add Missing Detection for KNOWN-BAD File\n\n**File**: %s\n**Problem**: Not flagged as suspicious/hostile\n**Task**: Detect malicious behavior\n\n*Note: Skip if genuinely benign (README, docs, unmodified dependency)*\n", path)
		taskBlock = badPromptTask
		debugCmd = path
	}

	debug := fmt.Sprintf(debugCommands, dissectBin, debugCmd, dissectBin, debugCmd, dissectBin, debugCmd)

	return fmt.Sprintf("%s\n%s\n\n%s\n\n%s\n\n%s\n\nTraits: %s/traits/", header, keyConstraints, taskBlock, successCriteria, debug, repoRoot)
}

type config struct {
	db          *sql.DB
	dirs        []string
	repoRoot    string
	dissectBin  string // Path to dissect binary
	provider    string
	model       string
	sampleDir   string
	timeout     time.Duration
	knownGood   bool
	knownBad    bool
	useCargo    bool
	flush       bool
	rescanAfter int // Number of files to review before restarting scan (0 = disabled)
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
			src.Close() //nolint:errcheck
			dst.Close() //nolint:errcheck
			return nil, fmt.Errorf("extract file: %w", err)
		}
		src.Close() //nolint:errcheck
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
			sizeM, errM := fileSize(m.ExtractedPath)
			sizeL, errL := fileSize(largest.ExtractedPath)
			if errM == nil && errL == nil && sizeM > sizeL {
				largest = &archive.Members[i]
			}
		}
	}

	return
}

// fileSize returns the size of a file.
func fileSize(path string) (int64, error) {
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
	rescanAfter := flag.Int("rescan-after", 1, "Restart scan after reviewing N files to verify fixes (0 = disabled)")

	flag.Parse()

	dirs := flag.Args()
	if len(dirs) == 0 {
		log.Fatal("At least one directory is required as an argument")
	}
	for _, dir := range dirs {
		if info, err := os.Stat(dir); err != nil {
			if os.IsNotExist(err) {
				log.Fatalf("Directory does not exist: %s", dir)
			}
			log.Fatalf("Cannot access directory %s: %v", dir, err)
		} else if !info.IsDir() {
			log.Fatalf("Not a directory: %s", dir)
		}
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
	defer os.RemoveAll(sampleDir) //nolint:errcheck,gosec // best-effort cleanup
	defer db.Close()              //nolint:errcheck,gosec // best-effort cleanup

	cfg := &config{
		dirs:        dirs,
		repoRoot:    resolvedRoot,
		provider:    *provider,
		model:       *model,
		timeout:     *timeout,
		knownGood:   *knownGood,
		knownBad:    *knownBad,
		useCargo:    *useCargo,
		flush:       *flush,
		db:          db,
		sampleDir:   sampleDir,
		rescanAfter: *rescanAfter,
	}

	ctx := context.Background()

	// Build or locate dissect binary
	if *useCargo {
		fmt.Fprint(os.Stderr, "Building release binary with cargo build --release...\n")

		cmd := exec.CommandContext(ctx, "cargo", "build", "--release")
		cmd.Dir = resolvedRoot

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			//nolint:gocritic // exitAfterDefer: defers won't run after log.Fatalf, acceptable for fatal errors
			log.Fatalf("cargo build --release failed: %v (%s)", err, stderr.String())
		}

		// Determine binary path based on OS
		binName := "dissect"
		if runtime.GOOS == "windows" {
			binName = "dissect.exe"
		}
		cfg.dissectBin = filepath.Join(resolvedRoot, "target", "release", binName)

		// Verify the binary exists
		if _, err := os.Stat(cfg.dissectBin); err != nil {
			//nolint:gocritic // exitAfterDefer: defers won't run after log.Fatalf, acceptable for fatal errors
			log.Fatalf("binary not found at %s: %v", cfg.dissectBin, err)
		}

		fmt.Fprintf(os.Stderr, "Built release binary: %s\n", cfg.dissectBin)
	} else {
		cfg.dissectBin = "dissect"
	}

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
	fmt.Fprintf(os.Stderr, "Streaming analysis of %v...\n\n", cfg.dirs)

	// Database mode (good/bad, not known-good/known-bad).
	dbMode := "bad"
	if cfg.knownGood {
		dbMode = "good"
	}

	// Use streaming analysis - process each archive as it completes.
	// Loop and restart after reviewing N files to catch fixed files.
	for {
		stats, err := streamAnalyzeAndReview(ctx, cfg, dbMode)
		if err != nil {
			log.Fatalf("Analysis failed: %v", err)
		}

		if !stats.shouldRestart {
			// No more files to review
			fmt.Fprintf(os.Stderr, "\nDone. Reviewed %d archives, %d standalone files. Skipped %d (cached), %d (no review needed).\n",
				stats.archivesReviewed, stats.standaloneReviewed, stats.skippedCached, stats.skippedNoReview)
			break
		}

		// Restart to verify fixes on the next batch
		fmt.Fprintf(os.Stderr, "Waiting 1 second before restarting scan...\n")
		time.Sleep(1 * time.Second)
	}

	fmt.Fprint(os.Stderr, "Run \"git diff traits/\" to see changes.\n")
}

// streamStats tracks streaming analysis statistics.
type streamStats struct {
	archivesReviewed   int
	standaloneReviewed int
	skippedCached      int
	skippedNoReview    int
	totalFiles         int
	shouldRestart      bool // Set to true when rescan limit reached
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
	filesReviewedCount int  // Count of files sent to LLM for review
	stopProcessing     bool // Set to true when rescan limit reached
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

	n := 0
	last := time.Now()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// If we've hit the rescan limit, just consume remaining lines without processing
		if state.stopProcessing {
			n++
			if time.Since(last) > 100*time.Millisecond {
				fmt.Fprintf(os.Stderr, "\r  Consuming remaining scan results... %d files", n)
				last = time.Now()
			}
			continue
		}

		var entry jsonlEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if entry.Type != "file" {
			continue
		}

		n++

		if time.Since(last) > 100*time.Millisecond {
			fmt.Fprintf(os.Stderr, "\r  Scanning... %d files processed", n)
			last = time.Now()
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

	fmt.Fprintf(os.Stderr, "\r  Scanned %d files total                    \n", n)
	return state.stats, nil
}

func buildDissectCommand(ctx context.Context, cfg *config) *exec.Cmd {
	sampleMaxRisk := "notable"
	if cfg.knownGood {
		sampleMaxRisk = "hostile"
	}

	args := []string{
		"--format", "jsonl",
		"--sample-dir", cfg.sampleDir,
		"--sample-max-risk", sampleMaxRisk,
	}
	args = append(args, cfg.dirs...)

	cmd := exec.CommandContext(ctx, cfg.dissectBin, args...)
	if cfg.useCargo {
		cmd.Dir = cfg.repoRoot // Run from repo root if using cargo
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
		if strings.Contains(f.Path, "##") {
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
		state.filesReviewedCount++

		// After reviewing N files, restart the scan to pick up any fixes (if rescanAfter > 0)
		if state.cfg.rescanAfter > 0 && state.filesReviewedCount >= state.cfg.rescanAfter {
			fmt.Fprintf(os.Stderr, "\n⚡ Reviewed %d files - restarting scan to verify fixes\n\n", state.cfg.rescanAfter)
			state.stopProcessing = true
			state.stats.shouldRestart = true
		}
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
		state.filesReviewedCount++

		// After reviewing N files, restart the scan to pick up any fixes (if rescanAfter > 0)
		if state.cfg.rescanAfter > 0 && state.filesReviewedCount >= state.cfg.rescanAfter {
			fmt.Fprintf(os.Stderr, "\n⚡ Reviewed %d files - restarting scan to verify fixes\n\n", state.cfg.rescanAfter)
			state.stopProcessing = true
			state.stats.shouldRestart = true
		}
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

	cmd := exec.CommandContext(ctx, cfg.dissectBin, "--format", "jsonl", testFile)
	if cfg.useCargo {
		cmd.Dir = cfg.repoRoot // Run from repo root if using cargo
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
		prompt = buildGoodPrompt(false, f.Path, 0, cfg.repoRoot, cfg.dissectBin)
		task = "Review for false positives (known-good collection)"
	} else {
		prompt = buildBadPrompt(false, f.Path, 0, cfg.repoRoot, cfg.dissectBin)
		task = "Find missing detections (known-bad collection)"
	}

	// Add suspicious/hostile findings for good files
	if cfg.knownGood {
		var suspicious, hostile []Finding
		for _, finding := range f.Findings {
			switch strings.ToLower(finding.Crit) {
			case "hostile":
				hostile = append(hostile, finding)
			case "suspicious":
				suspicious = append(suspicious, finding)
			}
		}
		if len(hostile) > 0 || len(suspicious) > 0 {
			prompt += "\n\n## Suspicious/Hostile Findings to Review\n"
			if len(hostile) > 0 {
				prompt += "**Hostile:**\n"
				for _, finding := range hostile {
					prompt += fmt.Sprintf("- `%s`: %s\n", finding.ID, finding.Desc)
				}
			}
			if len(suspicious) > 0 {
				prompt += "**Suspicious:**\n"
				for _, finding := range suspicious {
					prompt += fmt.Sprintf("- `%s`: %s\n", finding.ID, finding.Desc)
				}
			}
		}
	}

	if f.ExtractedPath != "" {
		prompt += fmt.Sprintf("\n\n## Extracted Sample\nThe file has been extracted to: %s\n"+
			"Use this path for binary analysis tools (radare2, strings, objdump, xxd, nm).", f.ExtractedPath)
	}

	fmt.Fprintf(os.Stderr, ">>> Preparing to invoke %s (session: %s)\n", cfg.provider, sid)

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
	var lines []string
	for ln := range strings.SplitSeq(prompt, "\n") {
		lines = append(lines, ln)
	}
	for i, ln := range lines {
		if i < 20 || i >= len(lines)-5 {
			fmt.Fprintf(os.Stderr, "│   %s\n", ln)
		} else if i == 20 {
			fmt.Fprintf(os.Stderr, "│   ... (%d lines of findings JSON) ...\n", len(lines)-25)
		}
	}
	fmt.Fprintln(os.Stderr, "└─────────────────────────────────────────────────────────────")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, ">>> %s working (timeout: %s)...\n", cfg.provider, cfg.timeout)
	fmt.Fprintln(os.Stderr)

	timedCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, ">>> About to start AI process with timeout %s\n", cfg.timeout)
	if err := runAIWithStreaming(timedCtx, cfg, prompt, sid); err != nil {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "<<< %s failed: %v\n", cfg.provider, err)
		return err
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "<<< %s finished successfully\n", cfg.provider)
	return nil
}

func invokeAIArchive(ctx context.Context, cfg *config, a *ArchiveAnalysis, sid string) error {
	problematic := archiveProblematicMembers(a, cfg.knownGood)

	fmt.Fprintf(os.Stderr, ">>> Preparing to invoke %s for archive (session: %s)\n", cfg.provider, sid)
	fmt.Fprintf(os.Stderr, ">>> Archive: %s (%d members, %d problematic)\n", a.ArchivePath, len(a.Members), len(problematic))

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
					src.Close() //nolint:errcheck
					dst.Close() //nolint:errcheck
					return fmt.Errorf("copy extracted file: %w", err)
				}
				src.Close() //nolint:errcheck
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
		prompt = buildGoodPrompt(true, a.ArchivePath, len(problematic), cfg.repoRoot, cfg.dissectBin)
		task = "Review archive for false positives (known-good collection)"
	} else {
		prompt = buildBadPrompt(true, a.ArchivePath, len(problematic), cfg.repoRoot, cfg.dissectBin)
		task = "Find missing detections in archive (known-bad collection)"
	}

	prompt += extractedInfo

	// Add suspicious/hostile findings summary for good archives
	if cfg.knownGood {
		var suspicious, hostile []Finding
		for _, m := range problematic {
			for _, finding := range m.Findings {
				switch strings.ToLower(finding.Crit) {
				case "hostile":
					hostile = append(hostile, finding)
				case "suspicious":
					suspicious = append(suspicious, finding)
				}
			}
		}
		if len(hostile) > 0 || len(suspicious) > 0 {
			prompt += "\n\n## Suspicious/Hostile Findings to Review\n"
			if len(hostile) > 0 {
				prompt += "**Hostile:**\n"
				for _, finding := range hostile {
					prompt += fmt.Sprintf("- `%s`: %s\n", finding.ID, finding.Desc)
				}
			}
			if len(suspicious) > 0 {
				prompt += "**Suspicious:**\n"
				for _, finding := range suspicious {
					prompt += fmt.Sprintf("- `%s`: %s\n", finding.ID, finding.Desc)
				}
			}
		}
	}

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
	var lines []string
	for ln := range strings.SplitSeq(prompt, "\n") {
		lines = append(lines, ln)
	}
	for i, ln := range lines {
		if i < 30 || i >= len(lines)-5 {
			fmt.Fprintf(os.Stderr, "│   %s\n", ln)
		} else if i == 30 {
			fmt.Fprintf(os.Stderr, "│   ... (%d lines) ...\n", len(lines)-35)
		}
	}
	fmt.Fprintln(os.Stderr, "└─────────────────────────────────────────────────────────────")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, ">>> %s working (timeout: %s)...\n", cfg.provider, cfg.timeout)
	fmt.Fprintln(os.Stderr)

	timedCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, ">>> About to start AI process with timeout %s\n", cfg.timeout)
	err = runAIWithStreaming(timedCtx, cfg, prompt, sid)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "<<< %s failed: %v\n", cfg.provider, err)
		return err
	}
	fmt.Fprintf(os.Stderr, "<<< %s finished successfully\n", cfg.provider)
	return nil
}

func runAIWithStreaming(ctx context.Context, cfg *config, prompt, sid string) error {
	var cmd *exec.Cmd

	fmt.Fprintf(os.Stderr, ">>> Setting up %s command (%s provider)\n", cfg.provider, cfg.provider)

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
			fmt.Fprintf(os.Stderr, ">>> Using Claude model: %s\n", cfg.model)
		}
		cmd = exec.CommandContext(ctx, "claude", args...)
	case "gemini":
		args := []string{
			"-p", prompt,
			"--verbose",
			"--yolo",
			"--output-format", "stream-json",
			"--resume", "latest",
		}
		if cfg.model != "" {
			args = append(args, "--model", cfg.model)
			fmt.Fprintf(os.Stderr, ">>> Using Gemini model: %s\n", cfg.model)
		} else {
			fmt.Fprintf(os.Stderr, ">>> Using default Gemini model\n")
		}
		cmd = exec.CommandContext(ctx, "gemini", args...)
	case "opencode":
		args := []string{"-p", prompt}
		if cfg.model != "" {
			args = append(args, "--model", cfg.model)
			fmt.Fprintf(os.Stderr, ">>> Using OpenCode model: %s\n", cfg.model)
		}
		cmd = exec.CommandContext(ctx, "opencode", args...)
	default:
		return fmt.Errorf("unknown provider: %s", cfg.provider)
	}

	cmd.Dir = cfg.repoRoot

	// Print the exact command being executed
	fmt.Fprintf(os.Stderr, ">>> Command: %s %s\n", cmd.Path, strings.Join(cmd.Args[1:], " "))
	fmt.Fprintf(os.Stderr, ">>> Working directory: %s\n", cmd.Dir)
	fmt.Fprintf(os.Stderr, ">>> Prompt size: %d bytes\n", len(prompt))

	if devNull, err := os.Open(os.DevNull); err == nil {
		cmd.Stdin = devNull
		defer devNull.Close() //nolint:errcheck,gosec // best-effort cleanup
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("could not create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("could not create stderr pipe: %w", err)
	}

	fmt.Fprintf(os.Stderr, ">>> Starting process...\n")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start %s: %w", cfg.provider, err)
	}
	fmt.Fprintf(os.Stderr, ">>> Process started (PID: %d)\n", cmd.Process.Pid)

	var stderrLines []string
	var stderrMu sync.Mutex
	done := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stdout)
		n := 0
		for scanner.Scan() {
			n++
			displayStreamEvent(scanner.Text())
		}
		fmt.Fprintf(os.Stderr, ">>> stdout closed after %d lines\n", n)
		done <- struct{}{}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		n := 0
		for scanner.Scan() {
			line := scanner.Text()
			n++
			fmt.Fprintf(os.Stderr, "  [stderr] %s\n", line)
			stderrMu.Lock()
			stderrLines = append(stderrLines, line)
			stderrMu.Unlock()
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, ">>> stderr closed after %d lines\n", n)
		}
		done <- struct{}{}
	}()

	finished := 0
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for finished < 2 {
		select {
		case <-done:
			finished++
			fmt.Fprintf(os.Stderr, ">>> Stream %d/2 finished\n", finished)
		case <-ticker.C:
			if cmd.ProcessState == nil {
				fmt.Fprintf(os.Stderr, ">>> Still running (PID: %d, timeout remaining: %s)\n",
					cmd.Process.Pid, timeRemaining(ctx))
			}
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "\n>>> [timeout] timed out, killing process...")
			io.Copy(io.Discard, stdout) //nolint:errcheck,gosec // drain pipes on timeout
			io.Copy(io.Discard, stderr) //nolint:errcheck,gosec // drain pipes on timeout
			cmd.Process.Kill()          //nolint:errcheck,gosec // best-effort kill on timeout
			fmt.Fprintf(os.Stderr, ">>> Process killed (PID: %d)\n", cmd.Process.Pid)
			return fmt.Errorf("timeout: %w", ctx.Err())
		}
	}

	fmt.Fprintf(os.Stderr, ">>> Waiting for process to exit...\n")
	err = cmd.Wait()
	exitCode := cmd.ProcessState.ExitCode()
	fmt.Fprintf(os.Stderr, ">>> Process exited with code %d\n", exitCode)

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errors.New("exceeded time limit")
		}
		stderrMu.Lock()
		allStderr := strings.Join(stderrLines, "\n")
		stderrMu.Unlock()

		// Build comprehensive error message
		errMsg := fmt.Sprintf("%s exited with code %d\n\n", cfg.provider, exitCode)
		errMsg += fmt.Sprintf("Command: %s %s\n", cmd.Path, strings.Join(cmd.Args[1:], " "))
		errMsg += fmt.Sprintf("Working directory: %s\n", cmd.Dir)

		if allStderr != "" {
			errMsg += fmt.Sprintf("\nFull stderr output:\n%s\n", allStderr)
		} else {
			errMsg += "\n(no stderr output)\n"
		}

		fmt.Fprintf(os.Stderr, "\n>>> %s\n", errMsg)
		return fmt.Errorf("%s", errMsg)
	}
	return nil
}

// timeRemaining returns a human-readable string for remaining context time.
func timeRemaining(ctx context.Context) string {
	deadline, ok := ctx.Deadline()
	if !ok {
		return "unlimited"
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return "0s"
	}
	if remaining < time.Minute {
		return fmt.Sprintf("%ds", int(remaining.Seconds()))
	}
	if remaining < time.Hour {
		return fmt.Sprintf("%dm%ds", int(remaining.Minutes()), int(remaining.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(remaining.Hours()), int(remaining.Minutes())%60)
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
	defer f.Close() //nolint:errcheck,gosec // best-effort cleanup

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
