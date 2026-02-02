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

const knownGoodPrompt = `Tune DISSECT traits for this known-good file.

## Input
- **File:** %s (KNOWN-GOOD)
- **Findings:** %s

## Goal
Fix MISLABELED findings. Suspicious findings are OK if the code actually does suspicious things - only fix incorrect labels (e.g., "obj/c2/beacon" for a simple HTTP client).

## Process
1. Read RULES.md and TAXONOMY.md
2. Analyze what the file actually does
3. Fix mislabeled findings (in priority order):
   - **Taxonomy** - Move to correct tier (cap/comm/http/client not obj/c2/beacon)
   - **Patterns** - Make regex more specific
   - **Exclusions** - ` + "`not:`" + ` to filter false matches
   - **Exceptions** - ` + "`unless:`" + ` or ` + "`downgrade:`" + ` (last resort)

## Constraints
- Traits live in %s/traits/
- Reorganize or deduplicate traits rather than deleting them
- Only analyze the file above, not other files in the directory/archive
- Skip cargo test

## Debugging Rules
Use ` + "`dissect test-rules <file> --rules \"rule-id\"`" + ` to debug why specific rules match or fail.
Use ` + "`dissect test-match <file> --type string --method contains --pattern \"pattern\"`" + ` to test individual conditions.

## Validate
Run ` + "`dissect %s --format jsonl`" + ` - findings should accurately describe actual capabilities.`

const knownBadPrompt = `Tune DISSECT to detect this malware's capabilities.

## Input
- **File:** %s (from KNOWN-BAD collection)
- **Findings:** %s
- **Problem:** Not flagged suspicious/hostile - find what's missing

## Process
1. Read RULES.md and TAXONOMY.md
2. Reverse engineer the file: radare2, nm, strings, objdump, xxd
3. Create/modify traits for detected capabilities

## Detection Philosophy
Write GENERIC behavioral patterns, not file-specific signatures:
- Combine capabilities into objectives (cap/comm/socket + cap/exec/shell → obj/c2/reverse-shell)
- Cross-language when possible (base64+exec works in Python, JS, Shell)
- Use cap/ for neutral mechanics, obj/ for attacker intent, known/ only for malware-family markers

## Constraints
- Traits live in %s/traits/
- Only analyze the file above, not other files in the directory/archive
- **Skip benign files** - While rare, known-bad collections (especially supply-chain attacks) may contain legitimately benign files like READMEs, docs, tests, or unmodified dependencies. If the file is genuinely benign, skip it.
- Skip cargo test

## Debugging Rules
Use ` + "`dissect test-rules <file> --rules \"rule-id\"`" + ` to debug why specific rules match or fail.
Use ` + "`dissect test-match <file> --type string --method contains --pattern \"pattern\"`" + ` to test individual conditions.
Particularly useful for complex composites that combine multiple traits with all:/any:/none: logic.

## Validate
Run ` + "`dissect %s --format jsonl`" + ` - file should be suspicious or hostile.
Suspicious is OK if hostility is hard to prove.`

const fixPromptTemplate = `DISSECT failed to run. Fix it.

## Error
Command: dissect %s --format jsonl
Output: %s

## Likely Causes
- Invalid YAML in traits/*.yaml (check file/line in error)
- Rust build error (run: cargo build --release)

## Fix Process
1. Diagnose from error message
2. Edit the broken file
3. Re-run: dissect %s --format jsonl
4. Repeat until it works

## Constraints
- Trait files: %s/traits/
- Syntax reference: RULES.md`

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
}

// Finding represents a matched trait/capability.
type Finding struct {
	ID   string `json:"id"`
	Crit string `json:"crit"`
	Desc string `json:"desc"`
}

// FileAnalysis represents a single analyzed file.
type FileAnalysis struct {
	Path     string    `json:"path"`
	Risk     string    `json:"risk"`
	Findings []Finding `json:"findings"`
}

// jsonlEntry represents a single JSONL line from streaming output.
type jsonlEntry struct {
	Type     string    `json:"type"`
	Path     string    `json:"path"`
	FileType string    `json:"file_type"`
	Risk     string    `json:"risk"`
	Findings []Finding `json:"findings"`
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

	// Filter to files needing review
	var toReview []FileAnalysis
	var skippedCached int
	for _, f := range files {
		if !needsReview(f, cfg.knownGood) {
			continue
		}

		// Check if already analyzed
		h, err := hashFile(f.Path)
		if err != nil {
			log.Printf("Warning: could not hash %s: %v", f.Path, err)
			toReview = append(toReview, f)
			continue
		}

		if wasAnalyzed(cfg.db, h, dbMode) {
			skippedCached++
			continue
		}

		toReview = append(toReview, f)
	}

	fmt.Fprintf(os.Stderr, "Found %d files, %d need review", len(files), len(toReview))
	if skippedCached > 0 {
		fmt.Fprintf(os.Stderr, " (%d skipped, previously analyzed)", skippedCached)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr)

	critRank := map[string]int{"inert": 0, "notable": 1, "suspicious": 2, "hostile": 3}

	for i, f := range toReview {
		sid := generateSessionID()

		// Print findings summary
		fmt.Fprintf(os.Stderr, "[%d/%d] Reviewing: %s\n", i+1, len(toReview), f.Path)
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

		fmt.Fprintf(os.Stderr, "\n--- Completed %s [%d/%d] ---\n\n", f.Path, i+1, len(toReview))
	}

	fmt.Fprintf(os.Stderr, "Done. Reviewed %d files.\n", len(toReview))
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
	var cmd *exec.Cmd
	if cfg.useCargo {
		cmd = exec.CommandContext(ctx, "cargo", "run", "--release", "--", "--format", "jsonl", cfg.dir)
		cmd.Dir = cfg.repoRoot
	} else {
		cmd = exec.CommandContext(ctx, "dissect", "--format", "jsonl", cfg.dir)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, errors.New(msg)
		}
		return nil, fmt.Errorf("dissect error: %w", err)
	}

	// Parse JSONL output
	var files []FileAnalysis
	scanner := bufio.NewScanner(strings.NewReader(stdout.String()))
	scanner.Buffer(make([]byte, 128*1024*1024), 128*1024*1024) // 128MB for large malware
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
				Path:     entry.Path,
				Risk:     entry.Risk,
				Findings: entry.Findings,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading JSONL output: %w", err)
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
	findingsJSON, err := json.MarshalIndent(f.Findings, "", "  ")
	if err != nil {
		log.Printf("Warning: could not marshal findings: %v", err)
		findingsJSON = []byte("[]")
	}

	var prompt, task string
	if cfg.knownGood {
		prompt = fmt.Sprintf(knownGoodPrompt, f.Path, string(findingsJSON), cfg.repoRoot, f.Path)
		task = "Review for false positives (known-good collection)"
	} else {
		prompt = fmt.Sprintf(knownBadPrompt, f.Path, string(findingsJSON), cfg.repoRoot, f.Path)
		task = "Find missing detections (known-bad collection)"
	}

	// Count criticalities for summary
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
		cmd = exec.CommandContext(ctx, "claude",
			"-p", prompt,
			"--verbose",
			"--output-format", "stream-json",
			"--dangerously-skip-permissions",
			"--session-id", sid,
		)
	case "gemini":
		cmd = exec.CommandContext(ctx, "gemini", "-p", prompt)
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
