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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
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

## Validate
Run ` + "`dissect %s --format jsonl`" + ` - findings should accurately describe actual capabilities.`

const knownBadPrompt = `Tune DISSECT to detect this malware's capabilities.

## Input
- **File:** %s (KNOWN-BAD malware)
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
- Skip if file is actually benign (README, docs)
- Skip cargo test

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
}

// DissectReport represents a single report in the JSON output array.
type DissectReport struct {
	SchemaVersion string         `json:"schema_version"`
	Files         []FileAnalysis `json:"files"`
}

// FileAnalysis represents a single analyzed file.
type FileAnalysis struct {
	Path     string    `json:"path"`
	Risk     string    `json:"risk"`
	Findings []Finding `json:"findings"`
}

// Finding represents a matched trait/capability.
type Finding struct {
	ID   string `json:"id"`
	Crit string `json:"crit"`
	Desc string `json:"desc"`
}

// Evidence represents proof of why a finding matched.
type Evidence struct {
	Method string `json:"method"`
	Value  string `json:"value"`
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

	cfg := &config{
		dir:       *dir,
		repoRoot:  *repoRoot,
		provider:  *provider,
		timeout:   *timeout,
		knownGood: *knownGood,
		knownBad:  *knownBad,
		useCargo:  *useCargo,
	}

	resolvedRoot, err := findRepoRoot(cfg.repoRoot)
	if err != nil {
		log.Fatalf("Could not detect repo root: %v. Use --repo-root flag.", err)
	}

	// Sanity check: run dissect on /bin/ls to catch code errors early
	if err := sanityCheck(context.Background(), cfg, resolvedRoot); err != nil {
		log.Fatalf("Sanity check failed: %v", err)
	}

	mode := "known-bad"
	if cfg.knownGood {
		mode = "known-good"
	}

	fmt.Fprintf(os.Stderr, "Provider: %s\n", cfg.provider)
	fmt.Fprintf(os.Stderr, "Mode: %s\n", mode)
	fmt.Fprintf(os.Stderr, "Repo root: %s\n", resolvedRoot)

	fmt.Fprintf(os.Stderr, "Scanning %s with dissect...\n", cfg.dir)

	ctx := context.Background()

	// Scan the entire directory with dissect (uses proper file type detection)
	sessionID := generateSessionID()
	scanResult, err := runDissectDirWithRetry(ctx, cfg, cfg.dir, resolvedRoot, sessionID)
	if err != nil {
		log.Fatalf("Failed to scan directory: %v", err)
	}

	// Collect all file analyses from the scan results
	var fileAnalyses []FileAnalysis
	for _, report := range scanResult {
		fileAnalyses = append(fileAnalyses, report.Files...)
	}

	// Pre-filter to find files needing review
	var toReview []FileAnalysis
	for _, fileAnalysis := range fileAnalyses {
		result := &DissectReport{Files: []FileAnalysis{fileAnalysis}}
		if shouldReview(result, cfg) {
			toReview = append(toReview, fileAnalysis)
		}
	}

	fmt.Fprintf(os.Stderr, "Found %d files, %d need review\n\n", len(fileAnalyses), len(toReview))

	for i, fileAnalysis := range toReview {
		file := fileAnalysis.Path
		result := &DissectReport{Files: []FileAnalysis{fileAnalysis}}
		fileSessionID := generateSessionID()

		fmt.Fprintf(os.Stderr, "[%d/%d] Reviewing: %s\n", i+1, len(toReview), file)
		printFindings(result)
		fmt.Fprint(os.Stderr, "  Invoking Claude...\n\n")

		if err := invokeAI(ctx, cfg, file, result, resolvedRoot, fileSessionID); err != nil {
			log.Fatalf("%s failed: %v", cfg.provider, err)
		}

		fmt.Fprintf(os.Stderr, "\n--- Completed %s [%d/%d] ---\n\n", file, i+1, len(toReview))
	}

	fmt.Fprintf(os.Stderr, "Done. Reviewed %d files.\n", len(toReview))
	fmt.Fprint(os.Stderr, "Run \"git diff traits/\" to see changes.\n")
}

func findRepoRoot(override string) (string, error) {
	if override != "" {
		return override, nil
	}

	cmd := exec.CommandContext(context.Background(), "git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// sanityCheck runs dissect on /bin/ls to catch code errors early.
// This allows fixing errors in an interactive window rather than mid-run.
func sanityCheck(ctx context.Context, cfg *config, repoRoot string) error {
	const testFile = "/bin/ls"
	fmt.Fprintf(os.Stderr, "Sanity check: running dissect on %s...\n", testFile)

	var cmd *exec.Cmd
	if cfg.useCargo {
		cmd = exec.CommandContext(ctx, "cargo", "run", "--release", "--", "--format", "jsonl", testFile)
		cmd.Dir = repoRoot
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

func runDissectDirWithRetry(ctx context.Context, cfg *config, dir, repoRoot, sessionID string) ([]DissectReport, error) {
	var lastErr error

	for attempt := range maxFixAttempts {
		result, err := runDissectDir(ctx, cfg, dir, repoRoot)
		if err == nil {
			return result, nil
		}

		lastErr = err
		fmt.Fprintf(os.Stderr, "Dissect failed (attempt %d/%d): %v\n", attempt+1, maxFixAttempts, err)
		fmt.Fprintf(os.Stderr, "Invoking %s to fix the issue...\n\n", cfg.provider)

		if fixErr := invokeAIFix(ctx, cfg, dir, err.Error(), repoRoot, sessionID); fixErr != nil {
			return nil, fmt.Errorf("%s failed while trying to fix dissect: %w", cfg.provider, fixErr)
		}
	}

	return nil, lastErr
}

// JsonlEntry represents a single JSONL line from streaming output.
type JsonlEntry struct {
	Type     string    `json:"type"`
	Path     string    `json:"path"`
	FileType string    `json:"file_type"`
	Risk     string    `json:"risk"`
	Findings []Finding `json:"findings"`
}

func runDissectDir(ctx context.Context, cfg *config, dir, repoRoot string) ([]DissectReport, error) {
	var cmd *exec.Cmd
	if cfg.useCargo {
		// Use --format jsonl for streaming output
		cmd = exec.CommandContext(ctx, "cargo", "run", "--release", "--", "--format", "jsonl", dir)
		cmd.Dir = repoRoot
	} else {
		cmd = exec.CommandContext(ctx, "dissect", "--format", "jsonl", dir)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg != "" {
			return nil, fmt.Errorf("%s", errMsg)
		}
		return nil, fmt.Errorf("dissect error: %w", err)
	}

	// Parse JSONL output - each line is a file or summary entry
	var files []FileAnalysis
	scanner := bufio.NewScanner(strings.NewReader(stdout.String()))
	// Increase buffer size to 128MB to handle malware files with massive strings/findings
	const maxScannerBuffer = 128 * 1024 * 1024
	scanner.Buffer(make([]byte, maxScannerBuffer), maxScannerBuffer)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry JsonlEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Skip lines that don't parse (could be debug output)
			continue
		}

		// Only process file entries, skip summary
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

	// Wrap in a single report for compatibility with existing code
	report := DissectReport{
		SchemaVersion: "2.0",
		Files:         files,
	}

	return []DissectReport{report}, nil
}

// shouldReview determines if a file needs Claude review based on mode.
// --good: Review files WITH suspicious/hostile findings (reduce false positives)
// --bad: Review files WITHOUT suspicious/hostile findings (find false negatives)
func shouldReview(result *DissectReport, cfg *config) bool {
	hasSuspiciousOrHostile := false
	for _, f := range result.Files {
		for _, finding := range f.Findings {
			crit := strings.ToLower(finding.Crit)
			if crit == "suspicious" || crit == "hostile" {
				hasSuspiciousOrHostile = true
				break
			}
		}
	}

	if cfg.knownGood {
		return hasSuspiciousOrHostile // Review FPs
	}
	return !hasSuspiciousOrHostile // Review FNs
}

func printFindings(result *DissectReport) {
	for _, f := range result.Files {
		var ids []string
		var maxCrit string
		for _, finding := range f.Findings {
			ids = append(ids, finding.ID)
			if critHigher(finding.Crit, maxCrit) {
				maxCrit = finding.Crit
			}
		}
		if len(ids) > 0 {
			fmt.Fprintf(os.Stderr, "  Risk: %s\n", maxCrit)
			fmt.Fprintf(os.Stderr, "  Findings: %s\n", strings.Join(ids, ", "))
		}
	}
}

func critHigher(a, b string) bool {
	order := map[string]int{"inert": 0, "notable": 1, "suspicious": 2, "hostile": 3}
	return order[strings.ToLower(a)] > order[strings.ToLower(b)]
}

func generateSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID (formatted as UUID-like)
		ts := time.Now().UnixNano()
		return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			ts>>32, (ts>>16)&0xffff, ts&0xffff, 0x4000, ts&0xffffffffffff)
	}
	// Set version 4 (random) UUID bits
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func invokeAIFix(ctx context.Context, cfg *config, file, errOutput, repoRoot, sessionID string) error {
	prompt := fmt.Sprintf(fixPromptTemplate,
		file,
		errOutput,
		file,
		repoRoot,
	)

	fmt.Fprintln(os.Stderr, "┌─────────────────────────────────────────────────────────────")
	fmt.Fprintf(os.Stderr, "│ %s FIX: %s\n", strings.ToUpper(cfg.provider), file)
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

	err := runAIWithStreaming(timedCtx, cfg, prompt, repoRoot, sessionID)

	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "<<< %s failed: %v\n", cfg.provider, err)
		return err
	}
	fmt.Fprintf(os.Stderr, "<<< %s finished\n", cfg.provider)
	return nil
}

func invokeAI(ctx context.Context, cfg *config, file string, result *DissectReport, repoRoot, sessionID string) error {
	var findings []Finding
	var crits []string
	for _, f := range result.Files {
		findings = append(findings, f.Findings...)
		for _, finding := range f.Findings {
			crits = append(crits, finding.Crit)
		}
	}

	findingsJSON, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		log.Printf("Warning: could not marshal findings: %v", err)
		findingsJSON = []byte("[]")
	}

	// Select prompt based on mode
	var prompt, task string
	if cfg.knownGood {
		prompt = fmt.Sprintf(knownGoodPrompt, file, string(findingsJSON), repoRoot, file)
		task = "Review for false positives (known-good collection)"
	} else {
		prompt = fmt.Sprintf(knownBadPrompt, file, string(findingsJSON), repoRoot, file)
		task = "Find missing detections (known-bad collection)"
	}

	// Count criticalities
	critCounts := make(map[string]int)
	for _, c := range crits {
		critCounts[strings.ToLower(c)]++
	}
	var critSummary []string
	for _, level := range []string{"hostile", "suspicious", "notable", "inert"} {
		if count := critCounts[level]; count > 0 {
			critSummary = append(critSummary, fmt.Sprintf("%d %s", count, level))
		}
	}

	fmt.Fprintln(os.Stderr, "┌─────────────────────────────────────────────────────────────")
	fmt.Fprintf(os.Stderr, "│ %s REVIEW: %s\n", strings.ToUpper(cfg.provider), file)
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

	err = runAIWithStreaming(timedCtx, cfg, prompt, repoRoot, sessionID)

	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "<<< %s failed: %v\n", cfg.provider, err)
		return err
	}
	fmt.Fprintf(os.Stderr, "<<< %s finished\n", cfg.provider)
	return nil
}

// runAIWithStreaming runs the AI provider and displays progress.
// It streams both stdout and stderr, and handles timeouts gracefully.
func runAIWithStreaming(ctx context.Context, cfg *config, prompt, repoRoot, sessionID string) error {
	var cmd *exec.Cmd

	switch cfg.provider {
	case "claude":
		cmd = exec.CommandContext(ctx, "claude",
			"-p", prompt,
			"--verbose",
			"--output-format", "stream-json",
			"--dangerously-skip-permissions",
			"--session-id", sessionID,
		)
	case "gemini":
		cmd = exec.CommandContext(ctx, "gemini",
			"-p", prompt,
		)
	case "opencode":
		cmd = exec.CommandContext(ctx, "opencode",
			"-p", prompt,
		)
	default:
		return fmt.Errorf("unknown provider: %s", cfg.provider)
	}

	cmd.Dir = repoRoot

	// Prevent stdin blocking
	devNull, err := os.Open(os.DevNull)
	if err == nil {
		cmd.Stdin = devNull
		defer devNull.Close() //nolint:errcheck // best-effort close of /dev/null
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
		return fmt.Errorf("could not start claude: %w", err)
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
	readersFinished := 0
	for readersFinished < 2 {
		select {
		case <-done:
			readersFinished++
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "\n  [timeout] Claude timed out, killing process...")
			// Drain remaining output
			drainPipe(stdout, "stdout")
			drainPipe(stderr, "stderr")
			if err := cmd.Process.Kill(); err != nil {
				log.Printf("Warning: could not kill claude process: %v", err)
			}
			return fmt.Errorf("timeout: %w", ctx.Err())
		}
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errors.New("claude exceeded time limit")
		}
		return fmt.Errorf("claude exited with error: %w", err)
	}
	return nil
}

// drainPipe reads remaining data from a pipe and displays it.
func drainPipe(r interface{ Read([]byte) (int, error) }, name string) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			for line := range strings.SplitSeq(string(buf[:n]), "\n") {
				if line != "" {
					fmt.Fprintf(os.Stderr, "  [%s remaining] %s\n", name, line)
				}
			}
		}
		if err != nil {
			break
		}
	}
}

// displayStreamEvent parses a stream-json line and displays relevant info.
func displayStreamEvent(line string) {
	var event map[string]any
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return
	}

	eventType, ok := event["type"].(string)
	if !ok {
		return
	}

	switch eventType {
	case "assistant":
		displayAssistantEvent(event)
	case "result":
		displayResultEvent(event)
	default:
		// Ignore other event types
	}
}

func displayAssistantEvent(event map[string]any) {
	msg, ok := event["message"].(map[string]any)
	if !ok {
		return
	}
	content, ok := msg["content"].([]any)
	if !ok {
		return
	}
	for _, c := range content {
		block, ok := c.(map[string]any)
		if !ok {
			continue
		}
		displayContentBlock(block)
	}
}

func displayContentBlock(block map[string]any) {
	blockType, ok := block["type"].(string)
	if !ok {
		return
	}

	switch blockType {
	case "tool_use":
		displayToolUse(block)
	case "text":
		if text, ok := block["text"].(string); ok && text != "" {
			fmt.Fprintf(os.Stderr, "  %s\n", text)
		}
	default:
		// Ignore other block types
	}
}

func displayToolUse(block map[string]any) {
	name, ok := block["name"].(string)
	if !ok {
		name = "unknown"
	}
	input, ok := block["input"].(map[string]any)
	if !ok {
		fmt.Fprintf(os.Stderr, "  [tool] %s\n", name)
		return
	}

	detail := extractToolDetail(input)
	if detail != "" {
		fmt.Fprintf(os.Stderr, "  [tool] %s: %s\n", name, detail)
	} else {
		fmt.Fprintf(os.Stderr, "  [tool] %s\n", name)
	}
}

func extractToolDetail(input map[string]any) string {
	// Try various input fields in order of preference
	if desc, ok := input["description"].(string); ok {
		return desc
	}
	if cmd, ok := input["command"].(string); ok {
		if len(cmd) > 80 {
			return cmd[:80] + "..."
		}
		return cmd
	}
	if pattern, ok := input["pattern"].(string); ok {
		return pattern
	}
	if filePath, ok := input["file_path"].(string); ok {
		return filePath
	}
	return ""
}

func displayResultEvent(event map[string]any) {
	if result, ok := event["result"].(string); ok && result != "" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "--- Result ---")
		fmt.Fprintln(os.Stderr, result)
	}
	if cost, ok := event["total_cost_usd"].(float64); ok {
		fmt.Fprintf(os.Stderr, "\n  Cost: $%.4f\n", cost)
	}
}
