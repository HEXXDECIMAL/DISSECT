// trait-basher orchestrates AI to tune DISSECT trait definitions.
//
// It scans a directory with dissect and invokes an AI assistant (Claude, Gemini,
// Codex, or Opencode) to analyze findings and modify/create traits as needed.
// Providers are tried in order; if one fails (e.g., quota exceeded), the next is tried.
//
// Usage:
//
//	trait-basher --dir /path/to/good-samples --good
//	trait-basher --dir /path/to/malware-samples --bad
//	trait-basher --dir /path/to/samples --bad --provider gemini,claude
//	trait-basher --dir /path/to/samples --bad --provider codex
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
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// fileEntry holds a file path with its finding summary for display.
type fileEntry struct {
	Path    string // Extracted path
	Summary string // e.g., "4 hostile, 2 suspicious"
	MaxCrit int    // For sorting (3=hostile, 2=suspicious, 1=notable)
	Total   int    // Total high-severity findings
}

// promptData holds values for prompt templates.
type promptData struct {
	Path        string      // Primary file path (extracted dir for archives, file path for standalone)
	ArchiveName string      // Archive basename for context (empty for standalone)
	Files       []fileEntry // Top files with findings (sorted by severity)
	DissectBin  string
	TraitsDir   string
	TaskBlock   string
	Count       int
	IsArchive   bool
}

var goodPromptTmpl = template.Must(template.New("good").Parse(`{{if .IsArchive -}}
# Known-Good Tuning (False Positive Reduction)
**Source**: {{.ArchiveName}}
**Scope**: {{.Count}} flagged files
## Priority Files
{{range .Files}}- {{.Path}} ({{.Summary}})
{{end}}
{{else -}}
# Known-Good Tuning (False Positive Reduction)
**File**: {{.Path}}
{{end}}
## Objective
Keep accurate behavior detections; revise only incorrect matches.

## False Positive Test
A finding is false positive only when the matched pattern does not represent actual behavior, context, or intent.
If behavior is real but severity is wrong, fix criticality; do not delete detection.

## Hard Constraints
- Read ` + "`RULES.md`" + `, ` + "`TAXONOMY.md`" + `, and ` + "`PRECISION.md`" + ` before edits.
- Edit logic only; preserve YAML formatting and file structure.
- Trait IDs must match what the query truly detects.
- For source code, prefer AST/semantic signals over raw-string coincidences.
- Keep trait placement taxonomy-accurate (` + "`cap/*`" + ` atomic capability, ` + "`obj/*`" + ` composed objective, ` + "`known/*`" + ` family/tool-specific).
- Prefer precise queries over ` + "`unless:`" + `/` + "`downgrade:`" + `; use those only as last resort.
- If a composite matches that seems to be missing a necessary restriction - the rule was likely broken during a refactor - fix it so that it's more specific
- Keep changes minimal, generic, and maintainable.

{{.TaskBlock}}

## Done When
- True behavior coverage is preserved.
- False positives are reduced.
- Criticality is appropriate (` + "`hostile`" + `, ` + "`suspicious`" + `, ` + "`notable`" + `, ` + "`inert`" + `).
- Re-run confirms improvement.

## Debug Loop
` + "```" + `
{{.DissectBin}} {{.Path}} --format jsonl
{{.DissectBin}} strings {{.Path}}
{{.DissectBin}} test-rules {{.Path}} --rules "rule-id"
{{.DissectBin}} test-match {{.Path}} --type string --pattern "X"
` + "```" + `

--format=jsonl is critical for reviewing all traits (even inert), both for accuracy, and knowing what hidden traits you can form intelligent composites with.

Traits: {{.TraitsDir}}`))

var badPromptTmpl = template.Must(template.New("bad").Parse(`{{if .IsArchive -}}
# Known-Bad Tuning (Missing Detection)
**Source**: {{.ArchiveName}}
**Scope**: {{.Count}} files to review
## Priority Files
{{range .Files}}- {{.Path}}{{if .Summary}} (current: {{.Summary}}){{end}}
{{end}}
{{else -}}
# Known-Bad Tuning (Missing Detection)
**File**: {{.Path}}
{{end}}
Skip genuinely benign content (README/docs/unmodified dependencies).

## Objective
Add high-signal detections for behaviors this sample family exhibits and current traits miss.

## Hard Constraints
- Read ` + "`RULES.md`" + `, ` + "`TAXONOMY.md`" + `, and ` + "`PRECISION.md`" + ` before edits.
- Edit logic only; preserve YAML formatting and file structure.
- Use reusable behavioral patterns, not sample-specific fingerprints.
- Keep trait IDs, location, and criticality semantically correct.
- For source code, prefer AST/semantic signals over raw-string coincidences.
- Some traits may have been mistakenly changed from 'symbol' to 'string' search: for AST-based languages, symbols are not in string literals.
- When there is overlap - choose improving existing traits over creating new traits
- Minimize future false positives at ecosystem scale.

{{.TaskBlock}}

## Done When
- Missing capabilities/objectives are detected with correct taxonomy.
- Traits remain accurate, well-described, generic and reusable.
- Criticality is appropriate.
- There are no duplicate traits shown in --format=jsonl mode
- There are no false positives or poorly described traits
- All unique or surprising traits have rules to feed into our ML analysis to find similar samples
- Re-run confirms improved coverage.

## Debug Loop
` + "```" + `
{{.DissectBin}} {{.Path}} --format jsonl
{{.DissectBin}} strings {{.Path}}
{{.DissectBin}} test-rules {{.Path}} --rules "rule-id"
{{.DissectBin}} test-match {{.Path}} --type string --pattern "X"
` + "```" + `

--format=jsonl is critical for reviewing all traits (even inert), both for accuracy, and knowing what hidden traits you can form intelligent composites with.

Traits: {{.TraitsDir}}`))

const goodTaskFile = `## Workflow
1. Validate taxonomy mapping first (` + "`cap/`" + ` = capability, ` + "`obj/`" + ` = objective).
2. Tighten matching logic before adding exclusions. Consult ` + "`PRECISION.md`" + ` for how to boost rule specificity:
   - add context (` + "`near:`" + ` / ` + "`all:`" + `)
   - restrict target type (` + "`for:`" + `)
   - bound broad rules (` + "`size_min/max`" + `)
3. Add ` + "`not:`" + ` filters only for proven benign collisions.
4. If behavior is correct but criticality is high, downgrade the criticality. Use ` + "`downgrade:`" + ` sparingly.
5. Use ` + "`unless:`" + ` only when precise query refinement is impractical.
6. If traits are renamed/removed, update all references (` + "`depends`" + `, composites, etc.).

## Taxonomy Guardrails
- ` + "`obj/c2/`" + ` requires control-channel behavior, not generic networking.
- ` + "`obj/exfil/`" + ` requires collection + transfer semantics.
- Generic HTTP/socket/crypto usually belongs under ` + "`cap/`" + `.

## Avoid
- Removing accurate behavior findings. Revise them instead.
`

const goodTaskArchive = goodTaskFile

const badTaskFile = `## Workflow
1. Reverse engineer with emphasis on high-signal artifacts (` + "`strings`" + `, control flow, imports/APIs, constants).
   - For binaries (archive member or standalone file), use ` + "`dissect strings`" + ` first to surface decoded/obfuscated content.
   - Use binary tooling when needed (` + "`radare2`" + `, ` + "`objdump`" + `, ` + "`nm`" + `) to confirm behavior before writing traits.
2. Enumerate behaviors that make the sample operationally distinct.
3. Map behavior to taxonomy:
   - ` + "`cap/`" + ` for atomic capabilities
   - ` + "`obj/`" + ` for composed attacker goals
   - ` + "`known/`" + ` only for well-supported malware-family identity
4. Build/repair capability traits first, then compose objective traits from those capabilities.
5. For ` + "`obj/*`" + ` with ` + "`crit: hostile`" + `, ensure composite complexity is >= 4. Consult ` + "`PRECISION.md`" + ` for the exact calculation algorithm.
6. Author generic reusable traits; avoid sample-only literals unless broadly durable.
7. Prefer multi-signal logic (` + "`all:`" + `, proximity, structural anchors) to suppress false positives.
8. If traits are renamed/removed, update all references (` + "`depends`" + `, composites, etc.).
9. If you see an existing rule that describes truly suspicious behavior, see if you can improve upon its precision and upgrade it to suspicious.
10. If you find a trait that should have caught this file but didn't, then the rule was likely broken during a refactor - fix it so that it applies to this case and others.

## Taxonomy Guardrails
- HTTP/socket alone: ` + "`cap/comm/`" + `, not ` + "`obj/c2/`" + `.
- C2 needs command/control semantics (beaconing, tasking, bidirectional control).
- Exfil needs data access + outbound transfer semantics.
- Keep generic crypto/network primitives out of objective traits unless composition justifies it.
- Consolidate multiple traits that demonstrate the same behavior when possible

## Avoid
- File-specific signatures as primary detection logic.
- Misplacing capabilities under ` + "`obj/`" + `.
- Overly broad rules that will not scale across large benign corpora.`

const badTaskArchive = badTaskFile

func buildGoodPrompt(isArchive bool, path, archiveName string, files []fileEntry, count int, root, bin string) string {
	task := goodTaskFile
	if isArchive {
		task = goodTaskArchive
	}
	var b bytes.Buffer
	_ = goodPromptTmpl.Execute(&b, promptData{ //nolint:errcheck // template is validated at init
		Path:        path,
		ArchiveName: archiveName,
		Files:       files,
		Count:       count,
		DissectBin:  bin,
		TraitsDir:   root + "/traits/",
		IsArchive:   isArchive,
		TaskBlock:   task,
	})
	return b.String()
}

func buildBadPrompt(isArchive bool, path, archiveName string, files []fileEntry, count int, root, bin string) string {
	task := badTaskFile
	if isArchive {
		task = badTaskArchive
	}
	var b bytes.Buffer
	_ = badPromptTmpl.Execute(&b, promptData{ //nolint:errcheck // template is validated at init
		Path:        path,
		ArchiveName: archiveName,
		Files:       files,
		Count:       count,
		DissectBin:  bin,
		TraitsDir:   root + "/traits/",
		IsArchive:   isArchive,
		TaskBlock:   task,
	})
	return b.String()
}

type config struct { //nolint:govet // field alignment optimized for readability, not size
	db          *sql.DB
	dirs        []string
	repoRoot    string
	dissectBin  string   // Path to dissect binary
	providers   []string // Ordered list of providers to try (fallback on failure)
	provider    string   // Current active provider (set during invocation)
	model       string
	extractDir  string // Directory where DISSECT extracts files
	timeout     time.Duration
	idleTimeout time.Duration // Kill LLM if no output for this duration
	rescanAfter int           // Number of files to review before restarting scan (0 = disabled)
	knownGood   bool
	knownBad    bool
	useCargo    bool
	flush       bool
}

const maxYAMLAutoFixAttempts = 3

// geminiDefaultModels is the ordered list of Gemini models to try when no model is specified.
// Falls back through these when quota is exhausted or errors occur.
var geminiDefaultModels = []string{
	"gemini-3-pro-preview",
	"gemini-3-flash-preview",
	"gemini-2.5-pro",
	"gemini-2.5-flash",
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
	ArchivePath     string
	Members         []FileAnalysis
	SummaryRisk     string    // Aggregated risk from archive summary entry
	SummaryFindings []Finding // Archive-level findings (zip-bomb, etc.)
}

// RealFileAnalysis groups a real file with all its encoded/decoded fragments.
// Fragments are decoded payloads (e.g., base64-decoded content) that should be
// analyzed together with their parent file.
type RealFileAnalysis struct {
	RealPath  string         // The real file path (stripped of ## fragment delimiters)
	Root      FileAnalysis   // The root/real file entry
	Fragments []FileAnalysis // All decoded fragment entries (if any)
}

// critRank maps criticality levels to numeric ranks for comparison.
var critRank = map[string]int{"inert": 0, "notable": 1, "suspicious": 2, "hostile": 3}

// archiveMemberStats finds the most notable file (with highest risk) and largest file.
func archiveMemberStats(archive *ArchiveAnalysis) (mostNotable, largest *FileAnalysis) {
	maxRisk := -1
	var largestSize int64

	for i, m := range archive.Members {
		// Find most notable
		for _, f := range m.Findings {
			rank := critRank[strings.ToLower(f.Crit)]
			if rank > maxRisk {
				maxRisk = rank
				mostNotable = &archive.Members[i]
			}
		}

		// Find largest (by extracted path size if available)
		if m.ExtractedPath != "" {
			if info, err := os.Stat(m.ExtractedPath); err == nil {
				if size := info.Size(); size > largestSize {
					largestSize = size
					largest = &archive.Members[i]
				}
			}
		}
	}

	return mostNotable, largest
}

// memberPath returns the member path within an archive,
// e.g., "archive.zip!!inner/file.py" -> "inner/file.py".
func memberPath(path string) string {
	if idx := strings.Index(path, "!!"); idx != -1 {
		return path[idx+2:]
	}
	return path
}

// archiveNeedsReview returns true if the archive needs review.
// Uses the archive summary risk when available (from DISSECT's aggregated output).
// For known-good archives: review if flagged (to reduce false positives).
// For known-bad archives: review if NOT flagged (missing detections).
func archiveNeedsReview(a *ArchiveAnalysis, knownGood bool) bool {
	// Use summary risk if available (preferred - avoids race conditions from parallel streaming)
	if a.SummaryRisk != "" {
		r := strings.ToLower(a.SummaryRisk)
		hasDetection := r == "suspicious" || r == "hostile"
		if knownGood {
			// Known-good: review if HAS detections (to reduce false positives)
			return hasDetection
		}
		// Known-bad: review only if NO detections (to add missing ones)
		return !hasDetection
	}

	// Fallback to member-based logic (legacy behavior, shouldn't happen with new DISSECT)
	if knownGood {
		// Known-good: review if ANY member has findings
		for _, m := range a.Members {
			if needsReview(m, knownGood) {
				return true
			}
		}
		return false
	}
	// Known-bad: review only if ALL members are undetected
	for _, m := range a.Members {
		if !needsReview(m, knownGood) {
			return false
		}
	}
	return true
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
	provider := flag.String("provider", "gemini,codex,claude,opencode", "AI providers (comma-separated, tries in order on failure)")
	model := flag.String("model", "", `Model to use (provider-specific). If not set, gemini
auto-tries models in order: gemini-3-pro-preview, gemini-3-flash-preview,
gemini-2.5-pro, gemini-2.5-flash. Popular choices:
  claude:   sonnet, opus, haiku
  gemini:   gemini-3-pro-preview, gemini-3-flash-preview,
            gemini-2.5-pro, gemini-2.5-flash, gemini-2.5-flash-lite
  codex:    gpt-5-codex, gpt-5-codex-mini, gpt-5
  opencode: gpt-4.1, gpt-4.1-mini, o4-mini, o3, moonshotai/kimi-k2.5`)
	repoRoot := flag.String("repo-root", "", "Path to DISSECT repo root (auto-detected if not specified)")
	useCargo := flag.Bool("cargo", true, "Use 'cargo run --release' instead of dissect binary")
	timeout := flag.Duration("timeout", 20*time.Minute, "Maximum time for each AI invocation")
	idleTimeout := flag.Duration("idle-timeout", 8*time.Minute, "Kill LLM if no output for this duration")
	flush := flag.Bool("flush", false, "Clear analysis cache and reprocess all files")
	rescanAfter := flag.Int("rescan-after", 4, "Restart scan after reviewing N files to verify fixes (0 = disabled)")

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

	// Parse and validate provider list
	var providers []string
	for p := range strings.SplitSeq(*provider, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			continue
		}
		// Allow provider:model syntax (e.g., gemini:gemini-2.5-pro)
		base := p
		if idx := strings.Index(p, ":"); idx != -1 {
			base = p[:idx]
		}
		if base != "claude" && base != "gemini" && base != "codex" && base != "opencode" {
			log.Fatalf("Unknown provider %q: must be claude, gemini, codex, or opencode", base)
		}
		providers = append(providers, p)
	}
	if len(providers) == 0 {
		log.Fatal("At least one provider must be specified")
	}

	// Expand bare "gemini" into model-specific entries for automatic fallback
	// Only expand if no explicit --model is set
	if *model == "" {
		var expanded []string
		for _, p := range providers {
			if p == "gemini" {
				// Expand to try each default model in order
				for _, m := range geminiDefaultModels {
					expanded = append(expanded, "gemini:"+m)
				}
			} else {
				expanded = append(expanded, p)
			}
		}
		providers = expanded
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

	// Clean up orphaned extract directories from crashed/killed previous runs.
	cleanupOrphanedExtractDirs()

	// Create temp directory for extracted samples with PID for easier debugging.
	// DISSECT writes files to <extract-dir>/<sha256[0:6]>/<relative-path>.
	// Directory persists across rescans for cache reuse.
	extractDir := filepath.Join(os.TempDir(), fmt.Sprintf("tbsh.%d", os.Getpid()))
	if err := os.MkdirAll(extractDir, 0o750); err != nil {
		db.Close() //nolint:errcheck,gosec // best-effort cleanup on fatal error
		log.Fatalf("Could not create extract directory: %v", err)
	}

	// Set up signal handler for cleanup on interrupt/termination.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintf(os.Stderr, "\nInterrupted. Cleaning up %s...\n", extractDir)
		os.RemoveAll(extractDir) //nolint:errcheck // best-effort cleanup on signal
		db.Close()               //nolint:errcheck // best-effort cleanup on signal
		os.Exit(1)
	}()

	defer os.RemoveAll(extractDir) //nolint:errcheck // best-effort cleanup
	defer db.Close()               //nolint:errcheck // best-effort cleanup

	cfg := &config{
		dirs:        dirs,
		repoRoot:    resolvedRoot,
		providers:   providers,
		provider:    providers[0], // Current active provider
		model:       *model,
		timeout:     *timeout,
		idleTimeout: *idleTimeout,
		knownGood:   *knownGood,
		knownBad:    *knownBad,
		useCargo:    *useCargo,
		flush:       *flush,
		db:          db,
		extractDir:  extractDir,
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
			log.Fatalf("binary not found at %s: %v", cfg.dissectBin, err)
		}

		fmt.Fprintf(os.Stderr, "Built release binary: %s\n", cfg.dissectBin)
	} else {
		cfg.dissectBin = "dissect"
	}

	// Sanity check: run dissect on /bin/ls to catch code errors early.
	for attempt := 1; ; attempt++ {
		if err := sanityCheck(ctx, cfg); err != nil {
			if !isYAMLTraitIssue(err.Error()) || attempt > maxYAMLAutoFixAttempts {
				log.Fatalf("Sanity check failed: %v", err)
			}
			if fixErr := invokeYAMLTraitFixer(ctx, cfg, "initial sanity check", err.Error(), attempt, maxYAMLAutoFixAttempts); fixErr != nil {
				log.Fatalf("Sanity check failed: %v (YAML trait auto-fix failed: %v)", err, fixErr)
			}
			fmt.Fprintf(os.Stderr, "Waiting 1 second before re-running sanity check...\n")
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

	mode := "known-bad"
	if cfg.knownGood {
		mode = "known-good"
	}

	// Display providers in a readable format (collapse gemini:model entries)
	displayProviders := formatProvidersForDisplay(cfg.providers)
	if cfg.model != "" {
		fmt.Fprintf(os.Stderr, "Providers: %s (model: %s)\n", displayProviders, cfg.model)
	} else {
		fmt.Fprintf(os.Stderr, "Providers: %s\n", displayProviders)
	}
	fmt.Fprintf(os.Stderr, "Mode: %s\n", mode)
	fmt.Fprintf(os.Stderr, "Repo root: %s\n", cfg.repoRoot)
	fmt.Fprintf(os.Stderr, "LLM timeout: %v (session max), %v (idle)\n", cfg.timeout, cfg.idleTimeout)
	fmt.Fprintf(os.Stderr, "Streaming analysis of %v...\n\n", cfg.dirs)

	// Database mode (good/bad, not known-good/known-bad).
	dbMode := "bad"
	if cfg.knownGood {
		dbMode = "good"
	}

	// Use streaming analysis - process each archive as it completes.
	// Loop and restart after reviewing N files to catch fixed files.
	yamlFixAttempts := 0
	for {
		// Reset to first provider on each scan iteration so all providers get re-evaluated
		cfg.provider = cfg.providers[0]

		stats, err := streamAnalyzeAndReview(ctx, cfg, dbMode)
		if err != nil {
			if isYAMLTraitIssue(err.Error()) && yamlFixAttempts < maxYAMLAutoFixAttempts {
				yamlFixAttempts++
				if fixErr := invokeYAMLTraitFixer(ctx, cfg, "scan/restart loop", err.Error(), yamlFixAttempts, maxYAMLAutoFixAttempts); fixErr != nil {
					log.Fatalf("Analysis failed: %v (YAML trait auto-fix failed: %v)", err, fixErr)
				}
				fmt.Fprintf(os.Stderr, "Waiting 1 second before restarting scan...\n")
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalf("Analysis failed: %v", err)
		}
		yamlFixAttempts = 0

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
	filesReviewedCount int // Count of files sent to LLM for review
}

// streamAnalyzeAndReview streams dissect output and reviews archives as they complete.
func streamAnalyzeAndReview(ctx context.Context, cfg *config, dbMode string) (*streamStats, error) {
	// Build dissect command with --extract-dir for file extraction.
	// DISSECT extracts all analyzed files to <extract-dir>/<sha256>/<relative-path>.
	args := []string{"--format", "jsonl", "--extract-dir", cfg.extractDir}
	args = append(args, cfg.dirs...)
	cmd := exec.CommandContext(ctx, cfg.dissectBin, args...) //nolint:gosec // dissectBin is built from trusted cargo
	if cfg.useCargo {
		cmd.Dir = cfg.repoRoot
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
		// Check if we need to restart (hit review limit)
		if state.stats.shouldRestart {
			clearProgressLine()
			fmt.Fprintf(os.Stderr, "⚡ Reviewed %d files - restarting scan to verify trait changes\n", state.cfg.rescanAfter)
			cmd.Process.Kill() //nolint:errcheck,gosec // intentional kill on restart
			cmd.Wait()         //nolint:errcheck,gosec // reap the process
			return state.stats, nil
		}

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

		// Extract archive path from "archive.zip!!inner/file.py" format
		ap := ""
		if idx := strings.Index(f.Path, "!!"); idx != -1 {
			ap = f.Path[:idx]
		}
		processFileEntry(ctx, state, f, ap)
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

func clearProgressLine() {
	fmt.Fprint(os.Stderr, "\r                                        \r")
}

func processFileEntry(ctx context.Context, st *streamState, f FileAnalysis, ap string) {
	switch {
	case ap == "" && st.currentArchivePath != "" && f.Path == st.currentArchivePath:
		// Archive summary entry - DISSECT now emits this after all member files
		// It contains aggregated risk/findings from all members, so we use it directly
		// instead of computing from members (which may have arrived out of order)
		if st.currentArchive != nil {
			// Update the archive with the summary's aggregated risk
			st.currentArchive.SummaryRisk = f.Risk
			st.currentArchive.SummaryFindings = f.Findings
			clearProgressLine()
			processCompletedArchive(ctx, st)
			st.currentArchive = nil
			st.currentArchivePath = ""
		} else {
			// This shouldn't happen - summary without members indicates a bug
			log.Printf("[warn] received archive summary for %q but no members were accumulated", f.Path)
		}
		return

	case ap == "":
		// Standalone file (not in an archive)
		if st.currentArchive != nil {
			clearProgressLine()
			processCompletedArchive(ctx, st)
			st.currentArchive = nil
			st.currentArchivePath = ""
		}

		// Strip fragment delimiter (e.g., "file.sh##base64@0" -> "file.sh")
		rp := f.Path
		if idx := strings.Index(f.Path, "##"); idx != -1 {
			rp = f.Path[:idx]
		}
		if rp == st.currentRealPath && st.currentRealFile != nil {
			// Same real file: add as fragment
			st.currentRealFile.Fragments = append(st.currentRealFile.Fragments, f)
			return
		}

		// Different real file: process previous and start new
		if st.currentRealFile != nil {
			clearProgressLine()
			processRealFile(ctx, st)
			st.currentRealFile = nil
			st.currentRealPath = ""
		}

		// Start new real file
		rf := &RealFileAnalysis{
			RealPath:  rp,
			Fragments: []FileAnalysis{},
		}
		if strings.Contains(f.Path, "##") {
			// This entry itself is a fragment; root file entry may come later
			rf.Fragments = []FileAnalysis{f}
		} else {
			// This is the root file entry
			rf.Root = f
		}
		st.currentRealFile = rf
		st.currentRealPath = rp

	case ap != st.currentArchivePath:
		// Different archive: process everything pending
		if st.currentArchive != nil {
			clearProgressLine()
			processCompletedArchive(ctx, st)
		}
		if st.currentRealFile != nil {
			clearProgressLine()
			processRealFile(ctx, st)
			st.currentRealFile = nil
			st.currentRealPath = ""
		}
		st.currentArchive = &ArchiveAnalysis{
			ArchivePath: ap,
			Members:     []FileAnalysis{f},
		}
		st.currentArchivePath = ap

	default:
		// Same archive: just add to current archive members
		st.currentArchive.Members = append(st.currentArchive.Members, f)
	}
}

func processCompletedArchive(ctx context.Context, st *streamState) {
	a := st.currentArchive
	if a == nil || len(a.Members) == 0 {
		return
	}

	st.stats.totalFiles += len(a.Members)

	archiveName := filepath.Base(a.ArchivePath)

	if !archiveNeedsReview(a, st.cfg.knownGood) {
		mode := "bad"
		reason := "at least one file already detected"
		if st.cfg.knownGood {
			mode = "good"
			reason = "no files have suspicious/hostile findings"
		}
		fmt.Fprintf(os.Stderr, "  [skip] %s (--%-4s): %s\n", archiveName, mode, reason)
		st.stats.skippedNoReview++
		return
	}

	h := hashString(a.ArchivePath)
	if wasAnalyzed(ctx, st.cfg.db, h, st.dbMode) {
		fmt.Fprintf(os.Stderr, "  [skip] %s: already analyzed (cache hit)\n", archiveName)
		st.stats.skippedCached++
		return
	}

	prob := archiveProblematicMembers(a, st.cfg.knownGood)
	skip := len(a.Members) - len(prob)
	fmt.Fprintf(os.Stderr, "\n📦 %s\n", archiveName)
	fmt.Fprintf(os.Stderr, "   Files: %d total, %d need review, %d filtered\n", len(a.Members), len(prob), skip)

	// Log which files were filtered out
	if skip > 0 && skip <= 5 && st.cfg.knownGood {
		for _, m := range a.Members {
			if !needsReview(m, st.cfg.knownGood) {
				crits := ""
				for _, f := range m.Findings {
					crits += f.Crit + " "
				}
				if crits == "" {
					crits = "none"
				}
				fmt.Fprintf(os.Stderr, "      - %s (%s): not critical enough\n", filepath.Base(m.Path), strings.TrimSpace(crits))
			}
		}
	}

	fmt.Fprintf(os.Stderr, "   Files requiring review:\n")
	for i, m := range prob {
		if i >= 3 {
			fmt.Fprintf(os.Stderr, "   ... and %d more\n", len(prob)-3)
			break
		}
		counts := make(map[string]int)
		for _, f := range m.Findings {
			counts[strings.ToLower(f.Crit)]++
		}
		var parts []string
		for _, level := range []string{"hostile", "suspicious", "notable"} {
			if n := counts[level]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, level))
			}
		}
		// Show extracted path if available, otherwise just filename
		displayPath := filepath.Base(m.Path)
		if m.ExtractedPath != "" {
			displayPath = m.ExtractedPath
		}
		fmt.Fprintf(os.Stderr, "   - %s (%s)\n", displayPath, strings.Join(parts, ", "))
	}

	reason := "has suspicious/hostile findings"
	if st.cfg.knownBad {
		reason = "missing detections on known-bad sample"
	}
	fmt.Fprintf(os.Stderr, "   [review] Submitting to %s: %s\n", st.cfg.provider, reason)

	sid := generateSessionID()
	if err := invokeAIArchive(ctx, st.cfg, a, sid); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %s failed for %s: %v\n", st.cfg.provider, a.ArchivePath, err)
	} else {
		if err := markAnalyzed(ctx, st.cfg.db, h, st.dbMode); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not record analysis for %s: %v\n", a.ArchivePath, err)
		}
		st.stats.archivesReviewed++
		st.filesReviewedCount++

		// After reviewing N files, signal restart to pick up trait changes
		if st.cfg.rescanAfter > 0 && st.filesReviewedCount >= st.cfg.rescanAfter {
			st.stats.shouldRestart = true
		}
	}
}

func processRealFile(ctx context.Context, st *streamState) {
	rf := st.currentRealFile
	if rf == nil || rf.RealPath == "" {
		return
	}

	st.stats.totalFiles++

	if !realFileNeedsReview(rf, st.cfg.knownGood) {
		mode := "bad"
		reason := "already detected (has suspicious/hostile findings)"
		if st.cfg.knownGood {
			mode = "good"
			reason = "no suspicious/hostile findings"
		}
		fmt.Fprintf(os.Stderr, "  [skip] File %s (--%-4s): %s\n", filepath.Base(rf.RealPath), mode, reason)
		st.stats.skippedNoReview++
		return
	}

	h, err := hashFile(rf.RealPath)
	if err != nil {
		h = hashString(rf.RealPath)
	}
	if wasAnalyzed(ctx, st.cfg.db, h, st.dbMode) {
		fmt.Fprintf(os.Stderr, "  [skip] File %s: already analyzed (cache hit)\n", filepath.Base(rf.RealPath))
		st.stats.skippedCached++
		return
	}

	// Aggregate findings from root and all fragments
	agg := rf.Root
	if agg.Path == "" {
		agg.Path = rf.RealPath
	}
	for _, frag := range rf.Fragments {
		agg.Findings = append(agg.Findings, frag.Findings...)
	}

	fmt.Fprintf(os.Stderr, "\n📄 Standalone file: %s\n", rf.RealPath)
	if len(rf.Fragments) > 0 {
		fmt.Fprintf(os.Stderr, "   (with %d decoded fragment(s))\n", len(rf.Fragments))
	}

	var maxCrit string
	for _, f := range agg.Findings {
		if critRank[strings.ToLower(f.Crit)] > critRank[strings.ToLower(maxCrit)] {
			maxCrit = f.Crit
		}
	}
	if maxCrit != "" {
		fmt.Fprintf(os.Stderr, "   Risk: %s, Findings: %d\n", maxCrit, len(agg.Findings))
	}

	reason := "has suspicious/hostile findings"
	if st.cfg.knownBad {
		reason = "missing detections on known-bad sample"
	}
	fmt.Fprintf(os.Stderr, "   [review] Submitting to %s: %s\n", st.cfg.provider, reason)

	sid := generateSessionID()
	if err := invokeAI(ctx, st.cfg, agg, sid); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %s failed for %s: %v\n", st.cfg.provider, rf.RealPath, err)
	} else {
		if err := markAnalyzed(ctx, st.cfg.db, h, st.dbMode); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not record analysis for %s: %v\n", rf.RealPath, err)
		}
		st.stats.standaloneReviewed++
		st.filesReviewedCount++

		// After reviewing N files, signal restart to pick up trait changes
		if st.cfg.rescanAfter > 0 && st.filesReviewedCount >= st.cfg.rescanAfter {
			st.stats.shouldRestart = true
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

	cmd := exec.CommandContext(ctx, cfg.dissectBin, "--format", "jsonl", testFile) //nolint:gosec // dissectBin is built from trusted cargo
	if cfg.useCargo {
		cmd.Dir = cfg.repoRoot // Run from repo root if using cargo
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprint(os.Stderr, "\n=== SANITY CHECK FAILED ===\n")
		errText := strings.TrimSpace(stderr.String())
		if stderr.Len() > 0 {
			fmt.Fprintf(os.Stderr, "stderr:\n%s\n", stderr.String())
		}
		if stdout.Len() > 0 {
			fmt.Fprintf(os.Stderr, "stdout:\n%s\n", stdout.String())
		}
		if errText == "" {
			errText = strings.TrimSpace(stdout.String())
		}
		if errText != "" {
			return fmt.Errorf("dissect failed on %s: %w: %s", testFile, err, errText)
		}
		return fmt.Errorf("dissect failed on %s: %w", testFile, err)
	}

	fmt.Fprint(os.Stderr, "Sanity check passed.\n\n")
	return nil
}

func isYAMLTraitIssue(msg string) bool {
	s := strings.ToLower(msg)
	if strings.Contains(s, "trait configuration warning") {
		return true
	}
	if strings.Contains(s, "fix these issues in the yaml files") {
		return true
	}
	hasYAML := strings.Contains(s, ".yaml") || strings.Contains(s, ".yml") || strings.Contains(s, "yaml")
	hasTraitContext := strings.Contains(s, "trait") || strings.Contains(s, "traits/")
	return hasYAML && hasTraitContext
}

func buildYAMLTraitFixPrompt(cfg *config, phase, failureOutput string) string {
	return fmt.Sprintf(`Fix DISSECT trait YAML issues only.

Failure phase: %s

Error output:
%s

Hard requirements:
- Only edit existing YAML trait files under %s/traits/ (*.yaml or *.yml).
- Do NOT edit any Rust code, Go code, scripts, docs, tests, or non-YAML files.
- Focus only on YAML trait parser/configuration issues from the error output.
- Keep trait IDs, taxonomy, and intent intact unless needed to fix the YAML issue.
- Make minimal edits.

After editing, validate with:
%s --format jsonl /bin/ls

If validation still fails with YAML trait issues, continue fixing YAML until it passes.
When done, stop.`,
		phase,
		failureOutput,
		cfg.repoRoot,
		cfg.dissectBin,
	)
}

func invokeYAMLTraitFixer(ctx context.Context, cfg *config, phase, failureOutput string, attempt, maxAttempts int) error {
	fmt.Fprintf(os.Stderr, "⚠️  YAML trait issue detected during %s (attempt %d/%d)\n", phase, attempt, maxAttempts)
	fmt.Fprintf(os.Stderr, "   [repair] Submitting YAML-only fix task to %s\n", strings.Join(cfg.providers, " → "))

	prompt := buildYAMLTraitFixPrompt(cfg, phase, failureOutput)
	sid := generateSessionID()

	// Try each provider in order until one succeeds
	var lastErr error
	for i, p := range cfg.providers {
		cfg.provider = p
		if i > 0 {
			fmt.Fprintf(os.Stderr, ">>> Trying next provider: %s\n", p)
		}

		tctx, cancel := context.WithTimeout(ctx, cfg.timeout)
		err := runAIWithStreaming(tctx, cfg, prompt, sid)
		cancel()

		if err == nil {
			return nil
		}

		lastErr = err
		fmt.Fprintf(os.Stderr, "<<< %s failed: %v\n", p, err)

		// Check if context was cancelled (user interrupt)
		if ctx.Err() != nil {
			return fmt.Errorf("interrupted: %w", ctx.Err())
		}
	}

	return fmt.Errorf("all providers failed, last error: %w", lastErr)
}

func invokeAI(ctx context.Context, cfg *config, f FileAnalysis, sid string) error {
	var prompt, task string
	if cfg.knownGood {
		prompt = buildGoodPrompt(false, f.Path, "", nil, 0, cfg.repoRoot, cfg.dissectBin)
		task = "Review for false positives (known-good collection)"
	} else {
		prompt = buildBadPrompt(false, f.Path, "", nil, 0, cfg.repoRoot, cfg.dissectBin)
		task = "Find missing detections (known-bad collection)"
	}

	// Add suspicious/hostile findings for good files
	if cfg.knownGood {
		var susp, host []Finding
		for _, fd := range f.Findings {
			switch strings.ToLower(fd.Crit) {
			case "hostile":
				host = append(host, fd)
			case "suspicious":
				susp = append(susp, fd)
			}
		}
		if len(host) > 0 || len(susp) > 0 {
			prompt += "\n\n## Suspicious/Hostile Findings to Review\n"
			if len(host) > 0 {
				prompt += "**Hostile:**\n"
				for _, fd := range host {
					prompt += fmt.Sprintf("- `%s`: %s\n", fd.ID, fd.Desc)
				}
			}
			if len(susp) > 0 {
				prompt += "**Suspicious:**\n"
				for _, fd := range susp {
					prompt += fmt.Sprintf("- `%s`: %s\n", fd.ID, fd.Desc)
				}
			}
		}
	}

	if f.ExtractedPath != "" {
		prompt += fmt.Sprintf("\n\n## Extracted Sample\nThe file has been extracted to: %s\n"+
			"Use this path for binary analysis tools (radare2, strings, objdump, xxd, nm).", f.ExtractedPath)
	}

	fmt.Fprintf(os.Stderr, ">>> Preparing to invoke %s (session: %s)\n", cfg.provider, sid)

	counts := make(map[string]int)
	for _, fd := range f.Findings {
		counts[strings.ToLower(fd.Crit)]++
	}
	var summary []string
	for _, level := range []string{"hostile", "suspicious", "notable", "inert"} {
		if n := counts[level]; n > 0 {
			summary = append(summary, fmt.Sprintf("%d %s", n, level))
		}
	}

	fmt.Fprintln(os.Stderr, "┌─────────────────────────────────────────────────────────────")
	fmt.Fprintf(os.Stderr, "│ %s REVIEW: %s\n", strings.ToUpper(cfg.provider), f.Path)
	fmt.Fprintf(os.Stderr, "│ Findings: %s\n", strings.Join(summary, ", "))
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

	// Try each provider in order until one succeeds
	var lastErr error
	for i, p := range cfg.providers {
		cfg.provider = p
		if i > 0 {
			fmt.Fprintf(os.Stderr, ">>> Trying next provider: %s\n", p)
		}
		fmt.Fprintf(os.Stderr, ">>> %s working (timeout: %s)...\n", p, cfg.timeout)
		fmt.Fprintln(os.Stderr)

		tctx, cancel := context.WithTimeout(ctx, cfg.timeout)
		err := runAIWithStreaming(tctx, cfg, prompt, sid)
		cancel()

		if err == nil {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "<<< %s finished successfully\n", p)
			return nil
		}

		lastErr = err
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "<<< %s failed: %v\n", p, err)

		// Check if context was cancelled (user interrupt)
		if ctx.Err() != nil {
			return fmt.Errorf("interrupted: %w", ctx.Err())
		}
	}

	return fmt.Errorf("all providers failed, last error: %w", lastErr)
}

func invokeAIArchive(ctx context.Context, cfg *config, a *ArchiveAnalysis, sid string) error {
	prob := archiveProblematicMembers(a, cfg.knownGood)
	archiveName := filepath.Base(a.ArchivePath)

	// Build file entries with finding summaries, sorted by severity.
	// DISSECT extracts to <extract-dir>/<sha256>/<relative-path>.
	var extractDir string
	var fileEntries []fileEntry

	// Helper to build a fileEntry from a FileAnalysis
	buildEntry := func(m FileAnalysis) fileEntry {
		counts := make(map[string]int)
		maxCrit := 0
		for _, f := range m.Findings {
			c := strings.ToLower(f.Crit)
			counts[c]++
			if r := critRank[c]; r > maxCrit {
				maxCrit = r
			}
		}
		var parts []string
		total := 0
		for _, level := range []string{"hostile", "suspicious", "notable"} {
			if n := counts[level]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, level))
				total += n
			}
		}
		path := m.ExtractedPath
		if path == "" {
			path = m.Path
		}
		return fileEntry{
			Path:    path,
			Summary: strings.Join(parts, ", "),
			MaxCrit: maxCrit,
			Total:   total,
		}
	}

	// For --good mode: use problematic files
	// For --bad mode: use all files (sorted by size as proxy for complexity)
	var sourceFiles []FileAnalysis
	if cfg.knownGood {
		sourceFiles = prob
	} else {
		sourceFiles = a.Members
	}

	for _, m := range sourceFiles {
		if m.ExtractedPath != "" {
			// Extract the SHA256 directory from first file
			if extractDir == "" {
				rel := strings.TrimPrefix(m.ExtractedPath, cfg.extractDir+"/")
				if idx := strings.Index(rel, "/"); idx > 0 {
					extractDir = filepath.Join(cfg.extractDir, rel[:idx])
				} else {
					extractDir = m.ExtractedPath
				}
			}
		}
		fileEntries = append(fileEntries, buildEntry(m))
	}

	// Sort by severity (hostile > suspicious > notable), then by count
	sort.Slice(fileEntries, func(i, j int) bool {
		if fileEntries[i].MaxCrit != fileEntries[j].MaxCrit {
			return fileEntries[i].MaxCrit > fileEntries[j].MaxCrit
		}
		return fileEntries[i].Total > fileEntries[j].Total
	})

	// Take top 10
	if len(fileEntries) > 10 {
		fileEntries = fileEntries[:10]
	}

	fmt.Fprintf(os.Stderr, ">>> Preparing to invoke %s (session: %s)\n", cfg.provider, sid)
	fmt.Fprintf(os.Stderr, ">>> Source: %s (%d files, %d problematic)\n", archiveName, len(a.Members), len(prob))
	if extractDir != "" {
		fmt.Fprintf(os.Stderr, ">>> Extracted to: %s\n", extractDir)
	}

	// Use extracted directory as the path for dissect commands
	dissectPath := extractDir
	if dissectPath == "" {
		dissectPath = a.ArchivePath // Fallback if no extraction
	}

	var prompt, task string
	if cfg.knownGood {
		prompt = buildGoodPrompt(true, dissectPath, archiveName, fileEntries, len(prob), cfg.repoRoot, cfg.dissectBin)
		task = "Review files for false positives (known-good collection)"
	} else {
		prompt = buildBadPrompt(true, dissectPath, archiveName, fileEntries, len(prob), cfg.repoRoot, cfg.dissectBin)
		task = "Find missing detections (known-bad collection)"
	}

	// Add suspicious/hostile findings summary for good archives
	if cfg.knownGood {
		var susp, host []Finding
		for _, m := range prob {
			for _, fd := range m.Findings {
				switch strings.ToLower(fd.Crit) {
				case "hostile":
					host = append(host, fd)
				case "suspicious":
					susp = append(susp, fd)
				}
			}
		}
		if len(host) > 0 || len(susp) > 0 {
			prompt += "\n\n## Suspicious/Hostile Findings to Review\n"
			if len(host) > 0 {
				prompt += "**Hostile:**\n"
				for _, fd := range host {
					prompt += fmt.Sprintf("- `%s`: %s\n", fd.ID, fd.Desc)
				}
			}
			if len(susp) > 0 {
				prompt += "**Suspicious:**\n"
				for _, fd := range susp {
					prompt += fmt.Sprintf("- `%s`: %s\n", fd.ID, fd.Desc)
				}
			}
		}
	}

	counts := make(map[string]int)
	for _, m := range a.Members {
		for _, fd := range m.Findings {
			counts[strings.ToLower(fd.Crit)]++
		}
	}
	var summary []string
	for _, level := range []string{"hostile", "suspicious", "notable", "inert"} {
		if n := counts[level]; n > 0 {
			summary = append(summary, fmt.Sprintf("%d %s", n, level))
		}
	}

	fmt.Fprintln(os.Stderr, "┌─────────────────────────────────────────────────────────────")
	fmt.Fprintf(os.Stderr, "│ %s REVIEW: %s\n", strings.ToUpper(cfg.provider), archiveName)
	fmt.Fprintf(os.Stderr, "│ Files: %d total, %d problematic\n", len(a.Members), len(prob))
	if extractDir != "" {
		fmt.Fprintf(os.Stderr, "│ Extracted: %s\n", extractDir)
	}
	fmt.Fprintf(os.Stderr, "│ Findings: %s\n", strings.Join(summary, ", "))
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

	// Try each provider in order until one succeeds
	var lastErr error
	for i, p := range cfg.providers {
		cfg.provider = p
		if i > 0 {
			fmt.Fprintf(os.Stderr, ">>> Trying next provider: %s\n", p)
		}
		fmt.Fprintf(os.Stderr, ">>> %s working (timeout: %s)...\n", p, cfg.timeout)
		fmt.Fprintln(os.Stderr)

		tctx, cancel := context.WithTimeout(ctx, cfg.timeout)
		err := runAIWithStreaming(tctx, cfg, prompt, sid)
		cancel()

		if err == nil {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "<<< %s finished successfully\n", p)
			return nil
		}

		lastErr = err
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "<<< %s failed: %v\n", p, err)

		// Check if context was cancelled (user interrupt)
		if ctx.Err() != nil {
			return fmt.Errorf("interrupted: %w", ctx.Err())
		}
	}

	return fmt.Errorf("all providers failed, last error: %w", lastErr)
}

func runAIWithStreaming(ctx context.Context, cfg *config, prompt, sid string) error {
	var cmd *exec.Cmd

	// Handle provider:model syntax (e.g., "gemini:gemini-2.5-pro")
	provider := cfg.provider
	modelOverride := ""
	if idx := strings.Index(provider, ":"); idx != -1 {
		modelOverride = provider[idx+1:]
		provider = provider[:idx]
	}

	// Build command args (prompt sent via stdin)
	switch provider {
	case "claude":
		args := []string{
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
			"--yolo",
			"--output-format", "stream-json",
			"--include-directories", cfg.repoRoot,
			"--include-directories", cfg.extractDir,
		}
		if home, err := os.UserHomeDir(); err == nil {
			args = append(args, "--include-directories", filepath.Join(home, "data"))
		}
		// Use model from provider:model syntax, or explicit --model flag
		if modelOverride != "" {
			args = append(args, "--model", modelOverride)
		} else if cfg.model != "" {
			args = append(args, "--model", cfg.model)
		}
		cmd = exec.CommandContext(ctx, "gemini", args...)
	case "codex":
		args := []string{"exec", "--json", "--full-auto", "--sandbox", "danger-full-access"}
		if cfg.model != "" {
			args = append(args, "--model", cfg.model)
		}
		args = append(args, "-")
		cmd = exec.CommandContext(ctx, "codex", args...)
	case "opencode":
		var args []string
		if cfg.model != "" {
			args = append(args, "--model", cfg.model)
		}
		cmd = exec.CommandContext(ctx, "opencode", args...)
	default:
		return fmt.Errorf("unknown provider: %s", cfg.provider)
	}

	cmd.Dir = cfg.repoRoot

	fmt.Fprintf(os.Stderr, ">>> %s %s\n", cmd.Path, strings.Join(cmd.Args[1:], " "))
	fmt.Fprintf(os.Stderr, ">>> Prompt: %d bytes via stdin\n", len(prompt))

	// Set up pipes
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", cfg.provider, err)
	}
	fmt.Fprintf(os.Stderr, ">>> PID %d\n", cmd.Process.Pid)

	// Write prompt to stdin, then close to signal EOF
	go func() {
		defer stdinPipe.Close()           //nolint:errcheck
		io.WriteString(stdinPipe, prompt) //nolint:errcheck
	}()

	var (
		output     []string
		outputMu   sync.Mutex
		lastActive = time.Now()
		activeMu   sync.Mutex
	)
	done := make(chan struct{})

	// Read stdout
	go func() {
		sc := bufio.NewScanner(stdoutPipe)
		sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
		for sc.Scan() {
			ln := sc.Text()
			displayStreamEvent(ln)
			outputMu.Lock()
			output = append(output, ln)
			outputMu.Unlock()
			activeMu.Lock()
			lastActive = time.Now()
			activeMu.Unlock()
		}
		done <- struct{}{}
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			goto waitForExit
		case <-ticker.C:
			if cmd.ProcessState == nil {
				activeMu.Lock()
				idle := time.Since(lastActive)
				activeMu.Unlock()

				if idle > cfg.idleTimeout {
					fmt.Fprintf(os.Stderr, "\n>>> Idle timeout (%v), killing...\n", cfg.idleTimeout)
					cmd.Process.Kill() //nolint:errcheck,gosec
					return fmt.Errorf("idle timeout: no output for %v", cfg.idleTimeout)
				}
			}
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "\n>>> Timeout, killing...")
			cmd.Process.Kill() //nolint:errcheck,gosec
			return fmt.Errorf("timeout: %w", ctx.Err())
		}
	}
waitForExit:

	err = cmd.Wait()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errors.New("exceeded time limit")
		}
		outputMu.Lock()
		all := strings.Join(output, "\n")
		outputMu.Unlock()
		return fmt.Errorf("%s failed (exit %d): %s", cfg.provider, cmd.ProcessState.ExitCode(), all)
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
// Handles both Claude format (type: assistant/result) and Gemini format (type: message).
func displayStreamEvent(line string) {
	var ev map[string]any
	if json.Unmarshal([]byte(line), &ev) != nil {
		return
	}

	switch ev["type"] {
	case "thread.started":
		if id, ok := ev["thread_id"].(string); ok && id != "" {
			fmt.Fprintf(os.Stderr, "  [codex] thread %s\n", id)
		}
	case "turn.started":
		fmt.Fprintln(os.Stderr, "  [codex] turn started")
	case "turn.completed":
		if usage, ok := ev["usage"].(map[string]any); ok {
			in, _ := usage["input_tokens"].(float64)   //nolint:errcheck // type assertion ok
			out, _ := usage["output_tokens"].(float64) //nolint:errcheck // type assertion ok
			if in > 0 || out > 0 {
				fmt.Fprintf(os.Stderr, "  [codex] tokens: in=%.0f out=%.0f\n", in, out)
			}
		}
	case "turn.failed":
		fmt.Fprintln(os.Stderr, "  [codex] turn failed")
	case "item/agentMessage/delta":
		if delta, ok := ev["delta"].(string); ok && delta != "" {
			fmt.Fprint(os.Stderr, delta)
			codexDeltaOpen = true
		} else if text, ok := ev["text"].(string); ok && text != "" {
			fmt.Fprint(os.Stderr, text)
			codexDeltaOpen = true
		}
	case "item/commandExecution/outputDelta":
		if delta, ok := ev["delta"].(string); ok && delta != "" {
			fmt.Fprint(os.Stderr, delta)
		} else if out, ok := ev["output"].(string); ok && out != "" {
			fmt.Fprint(os.Stderr, out)
		}
	case "item/fileChange/outputDelta":
		if delta, ok := ev["delta"].(string); ok && delta != "" {
			fmt.Fprint(os.Stderr, delta)
		} else if out, ok := ev["output"].(string); ok && out != "" {
			fmt.Fprint(os.Stderr, out)
		}
	case "item/plan/delta":
		if delta, ok := ev["delta"].(string); ok && delta != "" {
			fmt.Fprint(os.Stderr, delta)
		} else if text, ok := ev["text"].(string); ok && text != "" {
			fmt.Fprint(os.Stderr, text)
		}
	case "item.started", "item.completed":
		item, ok := ev["item"].(map[string]any)
		if !ok {
			return
		}
		itemType, _ := item["type"].(string) //nolint:errcheck // type assertion ok
		switch itemType {
		case "agent_message":
			if text, ok := item["text"].(string); ok && text != "" {
				fmt.Fprintln(os.Stderr, text)
			} else if codexDeltaOpen {
				fmt.Fprintln(os.Stderr)
			}
			codexDeltaOpen = false
		case "command_execution":
			if cmd, ok := item["command"].(string); ok && cmd != "" {
				fmt.Fprintf(os.Stderr, "  [tool] command: %s\n", cmd)
			}
		case "file_change":
			if path, ok := item["path"].(string); ok && path != "" {
				fmt.Fprintf(os.Stderr, "  [tool] file change: %s\n", path)
			}
		case "web_search":
			if q, ok := item["query"].(string); ok && q != "" {
				fmt.Fprintf(os.Stderr, "  [tool] web search: %s\n", q)
			}
		case "plan_update":
			fmt.Fprintln(os.Stderr, "  [tool] plan update")
		}
	case "error":
		if msg, ok := ev["message"].(string); ok && msg != "" {
			fmt.Fprintf(os.Stderr, "  [codex] error: %s\n", msg)
		}
	case "assistant":
		// Claude format: {"type":"assistant","message":{"content":[{"type":"text","text":"..."}]}}
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
				name, _ := b["name"].(string) //nolint:errcheck // type assertion ok, defaults to empty
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
				if t, ok := b["text"].(string); ok && t != "" {
					fmt.Fprintf(os.Stderr, "  %s\n", t)
				}
			}
		}

	case "message":
		// Gemini format: {"type":"message","role":"assistant","content":"...","delta":true}
		if ev["role"] == "assistant" {
			if content, ok := ev["content"].(string); ok && content != "" {
				fmt.Fprintln(os.Stderr, content)
			}
		}

	case "tool_call":
		// Gemini tool calls
		if name, ok := ev["name"].(string); ok {
			fmt.Fprintf(os.Stderr, "  [tool] %s\n", name)
		}

	case "result":
		if r, ok := ev["result"].(string); ok && r != "" {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "--- Result ---")
			fmt.Fprintln(os.Stderr, r)
		}
		if cost, ok := ev["total_cost_usd"].(float64); ok {
			fmt.Fprintf(os.Stderr, "\n  Cost: $%.4f\n", cost)
		}
	}
}

// codexDeltaOpen tracks whether we've printed streaming agent deltas and need a newline.
var codexDeltaOpen bool

// formatProvidersForDisplay collapses gemini:model entries into a single "gemini (4 models)"
// for cleaner display while showing the full fallback chain.
func formatProvidersForDisplay(providers []string) string {
	var result []string
	geminiCount := 0

	for _, p := range providers {
		if strings.HasPrefix(p, "gemini:") {
			geminiCount++
		} else if p == "gemini" {
			result = append(result, "gemini")
		} else {
			// Flush any accumulated gemini models before adding next provider
			if geminiCount > 0 {
				if geminiCount == 1 {
					result = append(result, "gemini")
				} else {
					result = append(result, fmt.Sprintf("gemini (%d models)", geminiCount))
				}
				geminiCount = 0
			}
			result = append(result, p)
		}
	}
	// Flush remaining gemini models
	if geminiCount > 0 {
		if geminiCount == 1 {
			result = append(result, "gemini")
		} else {
			result = append(result, fmt.Sprintf("gemini (%d models)", geminiCount))
		}
	}
	return strings.Join(result, " → ")
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

func openDB(ctx context.Context, flush bool) (*sql.DB, error) {
	// Determine config directory (platform-specific)
	var base string
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("config directory: %w", err)
		}
		base = filepath.Join(home, "Library", "Application Support")
	default:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			base = xdg
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("config directory: %w", err)
			}
			base = filepath.Join(home, ".config")
		}
	}
	dir := filepath.Join(base, "dissect")

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
	defer f.Close() //nolint:errcheck // best-effort cleanup

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
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [warn] DB query failed: %v\n", err)
		return false
	}
	return n > 0
}

func markAnalyzed(ctx context.Context, db *sql.DB, hash, mode string) error {
	_, err := db.ExecContext(ctx,
		"INSERT OR REPLACE INTO analyzed_files (file_hash, mode, analyzed_at) VALUES (?, ?, ?)",
		hash, mode, time.Now().Unix(),
	)
	return err
}

// cleanupOrphanedExtractDirs removes tbsh.<pid> directories where the
// owning process no longer exists. This handles cleanup after crashes or kill -9.
func cleanupOrphanedExtractDirs() {
	tmpDir := os.TempDir()
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return
	}

	const prefix = "tbsh."
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}

		// Extract PID from directory name
		pidStr := strings.TrimPrefix(entry.Name(), prefix)
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue // Not a valid PID format
		}

		// Check if process is still running (signal 0 = check existence)
		if err := syscall.Kill(pid, 0); err == nil {
			continue // Process still running, don't clean up
		}

		// Process is dead, clean up orphaned directory
		orphanPath := filepath.Join(tmpDir, entry.Name())
		fmt.Fprintf(os.Stderr, "Cleaning up orphaned extract directory: %s\n", orphanPath)
		os.RemoveAll(orphanPath) //nolint:errcheck // best-effort cleanup
	}
}
