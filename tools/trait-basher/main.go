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
	"bufio"
	"bytes"
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
   b) PATTERNS: Make regex/match more specific to avoid false matches
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
   b) PATTERNS: Make regex/match more specific to avoid false matches
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
6. Validate: Run dissect again - should be suspicious or hostile

## Debug Commands
` + "```" + `
dissect test-rules <file> --rules "rule-id"           # why does rule match/fail?
dissect test-match <file> --type string --pattern X   # test individual conditions
` + "```" + `

Traits: %s/traits/ | Skip cargo test | Focus on this archive`

const fixPromptTemplate = `Fix DISSECT error preventing analysis.

Command: dissect %s --format jsonl
Error: %s

Likely causes: Invalid YAML in traits/*.yaml (see file:line in error) or Rust build error (cargo build --release)

Fix the error, then verify: ` + "`dissect %s --format jsonl`" + `

Traits: %s/traits/ | Syntax: RULES.md`

const maxFixAttempts = 3

type config struct {
	dir       string
	repoRoot  string
	provider  string
	timeout   time.Duration
	knownGood bool
	knownBad  bool
	useCargo  bool
	flush     bool
	db        *sql.DB
	sampleDir string // Directory to extract samples for LLM analysis (radare2, etc.)
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
	Findings      []Finding `json:"findings"`
	ExtractedPath string    `json:"extracted_path,omitempty"`
}

// ArchiveAnalysis groups files from the same archive for review as a unit.
// Archives are the unit of resolution - a bad tar.gz with 100 good files and
// 1 bad file should be reviewed as a single archive.
type ArchiveAnalysis struct {
	ArchivePath string         // Path to the root archive
	Members     []FileAnalysis // All analyzed members of the archive
}

// rootArchive returns the root archive path from a path with archive delimiters.
// e.g., "archive.zip!!inner/file.py" -> "archive.zip"
// For non-archive paths, returns empty string.
func rootArchive(path string) string {
	if idx := strings.Index(path, "!!"); idx != -1 {
		return path[:idx]
	}
	return ""
}

// memberPath returns the member path within an archive.
// e.g., "archive.zip!!inner/file.py" -> "inner/file.py"
func memberPath(path string) string {
	if idx := strings.Index(path, "!!"); idx != -1 {
		return path[idx+2:]
	}
	return path
}

// groupByArchive groups files by their root archive.
// Returns a map from archive path to ArchiveAnalysis, plus a slice of
// standalone files that aren't in archives.
func groupByArchive(files []FileAnalysis) (map[string]*ArchiveAnalysis, []FileAnalysis) {
	archives := make(map[string]*ArchiveAnalysis)
	var standalone []FileAnalysis

	for _, f := range files {
		archivePath := rootArchive(f.Path)
		if archivePath == "" {
			standalone = append(standalone, f)
			continue
		}

		if archives[archivePath] == nil {
			archives[archivePath] = &ArchiveAnalysis{
				ArchivePath: archivePath,
			}
		}
		archives[archivePath].Members = append(archives[archivePath].Members, f)
	}

	return archives, standalone
}

// archiveNeedsReview returns true if any member of the archive needs review.
func archiveNeedsReview(a *ArchiveAnalysis, knownGood bool) bool {
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
	Findings      []Finding `json:"findings"`
	ExtractedPath string    `json:"extracted_path,omitempty"`
}

func main() {
	log.SetFlags(0)

	dir := flag.String("dir", "", "Directory to scan recursively (required)")
	knownGood := flag.Bool("good", false, "Review known-good files for false positives (suspicious/hostile findings)")
	knownBad := flag.Bool("bad", false, "Review known-bad files for false negatives (missing detections)")
	provider := flag.String("provider", "claude", "AI provider: claude, gemini, or opencode")
	repoRoot := flag.String("repo-root", "", "Path to DISSECT repo root (auto-detected if not specified)")
	useCargo := flag.Bool("cargo", true, "Use 'cargo run --release' instead of dissect binary")
	timeout := flag.Duration("timeout", 20*time.Minute, "Maximum time for each AI invocation")
	flush := flag.Bool("flush", false, "Clear analysis cache and reprocess all files")

	flag.Parse()

	if *dir == "" {
		log.Fatal("--dir is required")
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

	// Find repo root (for running dissect via cargo)
	resolvedRoot := *repoRoot
	if resolvedRoot == "" {
		cmd := exec.Command("git", "rev-parse", "--show-toplevel")
		out, err := cmd.Output()
		if err != nil {
			log.Fatalf("Could not detect repo root: %v. Use --repo-root flag.", err)
		}
		resolvedRoot = strings.TrimSpace(string(out))
	}

	db, err := openDB(*flush)
	if err != nil {
		log.Fatalf("Could not open database: %v", err)
	}
	defer db.Close()

	// Create temp directory for extracted samples (for LLM to use radare2, etc.)
	sampleDir, err := os.MkdirTemp("", "trait-basher-samples-*")
	if err != nil {
		log.Fatalf("Could not create sample directory: %v", err)
	}
	defer os.RemoveAll(sampleDir)

	cfg := &config{
		dir:       *dir,
		repoRoot:  resolvedRoot,
		provider:  *provider,
		timeout:   *timeout,
		knownGood: *knownGood,
		knownBad:  *knownBad,
		useCargo:  *useCargo,
		flush:     *flush,
		db:        db,
		sampleDir: sampleDir,
	}

	// Sanity check: run dissect on /bin/ls to catch code errors early
	if err := sanityCheck(context.Background(), cfg); err != nil {
		log.Fatalf("Sanity check failed: %v", err)
	}

	mode := "known-bad"
	if cfg.knownGood {
		mode = "known-good"
	}

	fmt.Fprintf(os.Stderr, "Provider: %s\n", cfg.provider)
	fmt.Fprintf(os.Stderr, "Mode: %s\n", mode)
	fmt.Fprintf(os.Stderr, "Repo root: %s\n", cfg.repoRoot)
	fmt.Fprintf(os.Stderr, "Scanning %s with dissect...\n", cfg.dir)

	ctx := context.Background()

	// Scan the entire directory with dissect
	sessionID := generateSessionID()
	files, err := runDissectDirWithRetry(ctx, cfg, sessionID)
	if err != nil {
		log.Fatalf("Failed to scan directory: %v", err)
	}

	// Database mode (good/bad, not known-good/known-bad)
	dbMode := "bad"
	if cfg.knownGood {
		dbMode = "good"
	}

	// Group files by archive - archives are the unit of review
	archives, standalone := groupByArchive(files)

	// Filter standalone files needing review
	var standaloneToReview []FileAnalysis
	var skippedCached int
	for _, f := range standalone {
		if !needsReview(f, cfg.knownGood) {
			continue
		}

		// Check if already analyzed
		h, err := hashFile(f.Path)
		if err != nil {
			log.Printf("Warning: could not hash %s: %v", f.Path, err)
			standaloneToReview = append(standaloneToReview, f)
			continue
		}

		if wasAnalyzed(cfg.db, h, dbMode) {
			skippedCached++
			continue
		}

		standaloneToReview = append(standaloneToReview, f)
	}

	// Filter archives needing review (any member needs review)
	var archivesToReview []*ArchiveAnalysis
	for _, a := range archives {
		if !archiveNeedsReview(a, cfg.knownGood) {
			continue
		}

		// Check if archive was already analyzed (hash the archive path itself)
		h := hashString(a.ArchivePath)
		if wasAnalyzed(cfg.db, h, dbMode) {
			skippedCached++
			continue
		}

		archivesToReview = append(archivesToReview, a)
	}

	// Count files by risk level
	riskCounts := make(map[string]int)
	for _, f := range files {
		riskCounts[strings.ToLower(f.Risk)]++
	}

	fmt.Fprint(os.Stderr, "\nScan summary:\n")
	fmt.Fprintf(os.Stderr, "  Total files: %d\n", len(files))
	fmt.Fprintf(os.Stderr, "  Archives: %d | Standalone files: %d\n", len(archives), len(standalone))
	for _, level := range []string{"hostile", "suspicious", "notable", "inert"} {
		if n := riskCounts[level]; n > 0 {
			fmt.Fprintf(os.Stderr, "  - %s: %d\n", level, n)
		}
	}

	totalToReview := len(archivesToReview) + len(standaloneToReview)
	fmt.Fprint(os.Stderr, "\nReview queue:\n")
	fmt.Fprintf(os.Stderr, "  Archives to review: %d\n", len(archivesToReview))
	fmt.Fprintf(os.Stderr, "  Standalone files to review: %d\n", len(standaloneToReview))
	if skippedCached > 0 {
		fmt.Fprintf(os.Stderr, "  Skipped (cached): %d\n", skippedCached)
	}
	fmt.Fprintln(os.Stderr)

	critRank := map[string]int{"inert": 0, "notable": 1, "suspicious": 2, "hostile": 3}

	reviewStart := time.Now()
	reviewCount := 0

	// Review archives first (they're higher priority as they contain problematic members)
	for i, a := range archivesToReview {
		sid := generateSessionID()

		// Calculate progress and rate
		pct := float64(reviewCount) / float64(totalToReview) * 100
		elapsed := time.Since(reviewStart)

		// Build progress line with rate/ETA if we have enough data
		progressLine := fmt.Sprintf("[%d/%d] (%.0f%%)", reviewCount+1, totalToReview, pct)
		if reviewCount > 0 && elapsed.Seconds() > 0 {
			rate := float64(reviewCount) / elapsed.Minutes()
			remaining := totalToReview - reviewCount
			eta := time.Duration(float64(remaining)/rate) * time.Minute
			progressLine = fmt.Sprintf("[%d/%d] (%.0f%%, %.1f/min, ~%s remaining)",
				reviewCount+1, totalToReview, pct, rate, eta.Truncate(time.Minute))
		}

		problematic := archiveProblematicMembers(a, cfg.knownGood)
		fmt.Fprintf(os.Stderr, "%s Reviewing archive: %s\n", progressLine, a.ArchivePath)
		fmt.Fprintf(os.Stderr, "  Problematic members: %d of %d\n", len(problematic), len(a.Members))

		// Show first few problematic members
		for j, m := range problematic {
			if j >= 3 {
				fmt.Fprintf(os.Stderr, "    ... and %d more\n", len(problematic)-3)
				break
			}
			var maxCrit string
			for _, finding := range m.Findings {
				if critRank[strings.ToLower(finding.Crit)] > critRank[strings.ToLower(maxCrit)] {
					maxCrit = finding.Crit
				}
			}
			fmt.Fprintf(os.Stderr, "    - %s (%s)\n", memberPath(m.Path), maxCrit)
		}
		fmt.Fprint(os.Stderr, "  Invoking Claude...\n\n")

		if err := invokeAIArchive(ctx, cfg, a, sid); err != nil {
			log.Fatalf("%s failed: %v", cfg.provider, err)
		}

		// Mark archive as analyzed
		h := hashString(a.ArchivePath)
		if err := markAnalyzed(cfg.db, h, dbMode); err != nil {
			log.Printf("Warning: could not record analysis for %s: %v", a.ArchivePath, err)
		}

		reviewCount++
		fmt.Fprintf(os.Stderr, "\n--- Completed archive %s [%d/%d] ---\n\n", a.ArchivePath, i+1, len(archivesToReview))
	}

	// Review standalone files
	for i, f := range standaloneToReview {
		sid := generateSessionID()

		// Calculate progress and rate
		pct := float64(reviewCount) / float64(totalToReview) * 100
		elapsed := time.Since(reviewStart)

		// Build progress line with rate/ETA if we have enough data
		progressLine := fmt.Sprintf("[%d/%d] (%.0f%%)", reviewCount+1, totalToReview, pct)
		if reviewCount > 0 && elapsed.Seconds() > 0 {
			rate := float64(reviewCount) / elapsed.Minutes()
			remaining := totalToReview - reviewCount
			eta := time.Duration(float64(remaining)/rate) * time.Minute
			progressLine = fmt.Sprintf("[%d/%d] (%.0f%%, %.1f/min, ~%s remaining)",
				reviewCount+1, totalToReview, pct, rate, eta.Truncate(time.Minute))
		}

		fmt.Fprintf(os.Stderr, "%s Reviewing: %s\n", progressLine, f.Path)
		if len(f.Findings) > 0 {
			var ids []string
			var maxCrit string
			for _, finding := range f.Findings {
				ids = append(ids, finding.ID)
				if critRank[strings.ToLower(finding.Crit)] > critRank[strings.ToLower(maxCrit)] {
					maxCrit = finding.Crit
				}
			}
			fmt.Fprintf(os.Stderr, "  Risk: %s\n", maxCrit)
			fmt.Fprintf(os.Stderr, "  Findings: %s\n", strings.Join(ids, ", "))
		}
		fmt.Fprint(os.Stderr, "  Invoking Claude...\n\n")

		if err := invokeAI(ctx, cfg, f, sid); err != nil {
			log.Fatalf("%s failed: %v", cfg.provider, err)
		}

		// Mark as analyzed after successful review
		if h, err := hashFile(f.Path); err == nil {
			if err := markAnalyzed(cfg.db, h, dbMode); err != nil {
				log.Printf("Warning: could not record analysis for %s: %v", f.Path, err)
			}
		}

		reviewCount++
		fmt.Fprintf(os.Stderr, "\n--- Completed %s [%d/%d] ---\n\n", f.Path, i+1, len(standaloneToReview))
	}

	totalElapsed := time.Since(reviewStart)
	if totalToReview > 0 && totalElapsed.Seconds() > 0 {
		rate := float64(totalToReview) / totalElapsed.Minutes()
		fmt.Fprintf(os.Stderr, "Done. Reviewed %d items (%d archives, %d files) in %s (%.1f/min).\n",
			totalToReview, len(archivesToReview), len(standaloneToReview),
			totalElapsed.Truncate(time.Second), rate)
	} else {
		fmt.Fprintf(os.Stderr, "Done. Reviewed %d items (%d archives, %d files).\n",
			totalToReview, len(archivesToReview), len(standaloneToReview))
	}
	fmt.Fprint(os.Stderr, "Run \"git diff traits/\" to see changes.\n")
}

// needsReview determines if a file needs AI review based on mode.
// --good: Review files WITH suspicious/hostile findings (reduce false positives)
// --bad: Review files WITHOUT suspicious/hostile findings (find false negatives)
func needsReview(f FileAnalysis, knownGood bool) bool {
	for _, finding := range f.Findings {
		c := strings.ToLower(finding.Crit)
		if c == "suspicious" || c == "hostile" {
			return knownGood // Has suspicious: review if --good (FP check)
		}
	}
	return !knownGood // No suspicious: review if --bad (FN check)
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

func runDissectDirWithRetry(ctx context.Context, cfg *config, sid string) ([]FileAnalysis, error) {
	var lastErr error
	for i := range maxFixAttempts {
		files, err := runDissectDir(ctx, cfg)
		if err == nil {
			return files, nil
		}
		lastErr = err
		fmt.Fprintf(os.Stderr, "Dissect failed (attempt %d/%d): %v\n", i+1, maxFixAttempts, err)
		fmt.Fprintf(os.Stderr, "Invoking %s to fix the issue...\n\n", cfg.provider)
		if err := invokeAIFix(ctx, cfg, err.Error(), sid); err != nil {
			return nil, fmt.Errorf("%s failed while trying to fix dissect: %w", cfg.provider, err)
		}
	}
	return nil, lastErr
}

func runDissectDir(ctx context.Context, cfg *config) ([]FileAnalysis, error) {
	// Determine sample extraction threshold based on mode:
	// --bad mode: extract inert/notable files (ones we need to detect)
	// --good mode: extract suspicious/hostile files (false positives to review)
	sampleMaxRisk := "notable"
	if cfg.knownGood {
		sampleMaxRisk = "hostile"
	}

	var cmd *exec.Cmd
	if cfg.useCargo {
		args := []string{"run", "--release", "--",
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

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("could not create stdout pipe: %w", err)
	}

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start dissect: %w", err)
	}

	// Stream and parse JSONL output with progress
	var files []FileAnalysis
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 128*1024*1024), 128*1024*1024) // 128MB for large malware

	startTime := time.Now()
	lastUpdate := time.Now()
	critCounts := make(map[string]int)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry jsonlEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue // Skip unparseable lines (debug output)
		}

		if entry.Type == "file" {
			files = append(files, FileAnalysis{
				Path:          entry.Path,
				Risk:          entry.Risk,
				Findings:      entry.Findings,
				ExtractedPath: entry.ExtractedPath,
			})
			critCounts[strings.ToLower(entry.Risk)]++

			// Update progress every 100ms or every 10 files
			if time.Since(lastUpdate) > 100*time.Millisecond || len(files)%10 == 0 {
				elapsed := time.Since(startTime)

				// Build criticality summary
				var critParts []string
				for _, level := range []string{"hostile", "suspicious", "notable", "inert"} {
					if n := critCounts[level]; n > 0 {
						critParts = append(critParts, fmt.Sprintf("%s:%d", level, n))
					}
				}
				critSummary := strings.Join(critParts, " ")

				if elapsed.Seconds() >= 1 {
					rate := float64(len(files)) / elapsed.Minutes()
					fmt.Fprintf(os.Stderr, "\r  Scanned %d files (%.1f/min) [%s]              ",
						len(files), rate, critSummary)
				} else {
					fmt.Fprintf(os.Stderr, "\r  Scanned %d files [%s]              ", len(files), critSummary)
				}
				lastUpdate = time.Now()
			}
		}
	}

	// Clear the progress line and print final count with criticality summary
	elapsed := time.Since(startTime)
	var critParts []string
	for _, level := range []string{"hostile", "suspicious", "notable", "inert"} {
		if n := critCounts[level]; n > 0 {
			critParts = append(critParts, fmt.Sprintf("%s:%d", level, n))
		}
	}
	critSummary := strings.Join(critParts, " ")

	if elapsed.Seconds() >= 1 && len(files) > 0 {
		rate := float64(len(files)) / elapsed.Minutes()
		fmt.Fprintf(os.Stderr, "\r  Scanned %d files in %s (%.1f/min) [%s]                    \n",
			len(files), elapsed.Truncate(time.Second), rate, critSummary)
	} else {
		fmt.Fprintf(os.Stderr, "\r  Scanned %d files [%s]                                      \n",
			len(files), critSummary)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading JSONL output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		if msg := strings.TrimSpace(stderrBuf.String()); msg != "" {
			return nil, errors.New(msg)
		}
		return nil, fmt.Errorf("dissect error: %w", err)
	}

	return files, nil
}

func invokeAIFix(ctx context.Context, cfg *config, errOutput, sid string) error {
	prompt := fmt.Sprintf(fixPromptTemplate, cfg.dir, errOutput, cfg.dir, cfg.repoRoot)

	fmt.Fprintln(os.Stderr, "┌─────────────────────────────────────────────────────────────")
	fmt.Fprintf(os.Stderr, "│ %s FIX: %s\n", strings.ToUpper(cfg.provider), cfg.dir)
	fmt.Fprintln(os.Stderr, "│ Task: Fix dissect error so it can analyze this file")
	fmt.Fprintln(os.Stderr, "├─────────────────────────────────────────────────────────────")
	fmt.Fprintln(os.Stderr, "│ Error:")
	for line := range strings.SplitSeq(errOutput, "\n") {
		fmt.Fprintf(os.Stderr, "│   %s\n", line)
	}
	fmt.Fprintln(os.Stderr, "└─────────────────────────────────────────────────────────────")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, ">>> %s working (timeout: %s)...\n", cfg.provider, cfg.timeout)
	fmt.Fprintln(os.Stderr)

	timedCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	err := runAIWithStreaming(timedCtx, cfg, prompt, sid)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "<<< %s failed: %v\n", cfg.provider, err)
		return err
	}
	fmt.Fprintf(os.Stderr, "<<< %s finished\n", cfg.provider)
	return nil
}

func invokeAI(ctx context.Context, cfg *config, f FileAnalysis, sid string) error {
	// Build prompt - LLM will run dissect itself to see findings
	var prompt, task string
	if cfg.knownGood {
		prompt = fmt.Sprintf(knownGoodPrompt, f.Path, f.Path, cfg.repoRoot)
		task = "Review for false positives (known-good collection)"
	} else {
		prompt = fmt.Sprintf(knownBadPrompt, f.Path, f.Path, cfg.repoRoot)
		task = "Find missing detections (known-bad collection)"
	}

	// Add extracted sample path if available (for radare2, strings, objdump analysis)
	if f.ExtractedPath != "" {
		prompt += fmt.Sprintf("\n\n## Extracted Sample\nThe file has been extracted to: %s\nUse this path for binary analysis tools (radare2, strings, objdump, xxd, nm).", f.ExtractedPath)
	}

	// Count criticalities for summary display
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

	// Build prompt - LLM will run dissect itself to see findings
	var prompt, task string
	if cfg.knownGood {
		prompt = fmt.Sprintf(knownGoodArchivePrompt, a.ArchivePath, len(problematic), a.ArchivePath, cfg.repoRoot)
		task = "Review archive for false positives (known-good collection)"
	} else {
		prompt = fmt.Sprintf(knownBadArchivePrompt, a.ArchivePath, len(problematic), a.ArchivePath, cfg.repoRoot)
		task = "Find missing detections in archive (known-bad collection)"
	}

	// Add extracted sample paths if available
	var extractedPaths []string
	for _, m := range problematic {
		if m.ExtractedPath != "" {
			extractedPaths = append(extractedPaths, fmt.Sprintf("- %s -> %s", memberPath(m.Path), m.ExtractedPath))
		}
	}
	if len(extractedPaths) > 0 {
		prompt += fmt.Sprintf("\n\n## Extracted Samples\nProblematic members have been extracted for binary analysis:\n%s\nUse these paths for radare2, strings, objdump, xxd, nm.", strings.Join(extractedPaths, "\n"))
	}

	// Count criticalities for summary display
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
	fmt.Fprintln(os.Stderr, "│ Prompt:")
	for _, line := range strings.Split(prompt, "\n") {
		fmt.Fprintf(os.Stderr, "│   %s\n", line)
	}
	fmt.Fprintln(os.Stderr, "└─────────────────────────────────────────────────────────────")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, ">>> %s working (timeout: %s)...\n", cfg.provider, cfg.timeout)
	fmt.Fprintln(os.Stderr)

	timedCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	err := runAIWithStreaming(timedCtx, cfg, prompt, sid)
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
		cmd = exec.CommandContext(ctx, "claude",
			"-p", prompt,
			"--verbose",
			"--output-format", "stream-json",
			"--dangerously-skip-permissions",
			"--session-id", sid,
		)
	case "gemini":
		cmd = exec.CommandContext(ctx, "gemini",
			"-p", prompt,
			"--yolo",
			"--output-format", "stream-json",
		)
	case "opencode":
		cmd = exec.CommandContext(ctx, "opencode", "-p", prompt)
	default:
		return fmt.Errorf("unknown provider: %s", cfg.provider)
	}

	cmd.Dir = cfg.repoRoot

	// Prevent stdin blocking
	if devNull, err := os.Open(os.DevNull); err == nil {
		cmd.Stdin = devNull
		defer devNull.Close()
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

	// Read stdout and stderr concurrently
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
			fmt.Fprintf(os.Stderr, "  [stderr] %s\n", scanner.Text())
		}
		done <- struct{}{}
	}()

	// Wait for both readers or context cancellation
	finished := 0
	for finished < 2 {
		select {
		case <-done:
			finished++
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "\n  [timeout] timed out, killing process...")
			io.Copy(io.Discard, stdout) // Drain pipes
			io.Copy(io.Discard, stderr)
			cmd.Process.Kill()
			return fmt.Errorf("timeout: %w", ctx.Err())
		}
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errors.New("exceeded time limit")
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
		msg, _ := ev["message"].(map[string]any)
		content, _ := msg["content"].([]any)
		for _, c := range content {
			b, _ := c.(map[string]any)
			switch b["type"] {
			case "tool_use":
				name, _ := b["name"].(string)
				if name == "" {
					name = "unknown"
				}
				input, ok := b["input"].(map[string]any)
				if !ok {
					fmt.Fprintf(os.Stderr, "  [tool] %s\n", name)
					continue
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
			case "text":
				if t, _ := b["text"].(string); t != "" {
					fmt.Fprintf(os.Stderr, "  %s\n", t)
				}
			}
		}
	case "result":
		if r, _ := ev["result"].(string); r != "" {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "--- Result ---")
			fmt.Fprintln(os.Stderr, r)
		}
		if cost, ok := ev["total_cost_usd"].(float64); ok {
			fmt.Fprintf(os.Stderr, "\n  Cost: $%.4f\n", cost)
		}
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

// Database functions for tracking analyzed files

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

func openDB(flush bool) (*sql.DB, error) {
	dir, err := configDir()
	if err != nil {
		return nil, fmt.Errorf("config directory: %w", err)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
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

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS analyzed_files (
			file_hash TEXT NOT NULL,
			mode TEXT NOT NULL,
			analyzed_at INTEGER NOT NULL,
			PRIMARY KEY (file_hash, mode)
		)
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	return db, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashString returns SHA256 hash of a string (for archive path caching)
func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func wasAnalyzed(db *sql.DB, hash, mode string) bool {
	var n int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM analyzed_files WHERE file_hash = ? AND mode = ?",
		hash, mode,
	).Scan(&n)
	return err == nil && n > 0
}

func markAnalyzed(db *sql.DB, hash, mode string) error {
	_, err := db.Exec(
		"INSERT OR REPLACE INTO analyzed_files (file_hash, mode, analyzed_at) VALUES (?, ?, ?)",
		hash, mode, time.Now().Unix(),
	)
	return err
}
