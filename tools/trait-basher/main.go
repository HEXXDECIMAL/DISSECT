// trait-basher orchestrates AI to tune DISSECT trait definitions.
//
// It scans a directory with dissect and invokes an AI assistant (Claude, Gemini,
// Codex, or Opencode) to analyze findings and modify/create traits as needed.
//
// Usage:
//
//	trait-basher --dir /path/to/good-samples --good
//	trait-basher --dir /path/to/malware-samples --bad
//	trait-basher --dir /path/to/samples --bad --provider gemini
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
# Fix False Positives in KNOWN-GOOD Files

**Source**: {{.ArchiveName}}
**Files**: {{.Count}} flagged as suspicious/hostile
**Task**: Remove false positive findings

## Top Files to Review (by severity)
{{range .Files}}- {{.Path}} ({{.Summary}})
{{end}}
{{else -}}
# Fix False Positives in KNOWN-GOOD File

**File**: {{.Path}}
**Problem**: Flagged as suspicious/hostile
**Task**: Remove false positive findings
{{end}}
## What Is a False Positive?
A **false positive** is a finding that DOES NOT match what the program actually does.
- If the program DOES execute code → "exec" finding is CORRECT, not a false positive
- If the program DOES read files → "file_read" finding is CORRECT, not a false positive
- If the program DOES open sockets → "socket" finding is CORRECT, not a false positive

A finding is only a false positive if:
- The rule incorrectly matched something that doesn't indicate that behavior
- The pattern is too broad and matches unrelated benign code
- The finding is in the wrong file or context
- The criticality is inappropriately high: "hostile" is a true and specific stop-everything-now concern, "suspicious" should genuinely be a concern, "notable" should accurately describe the defining characteristics of a program, "inert" should be uninteresting traits that many programs share.

**Expected**: Known-good software has findings! Notable and suspicious findings are normal if they accurately describe what the code does. The goal is ACCURATE findings, not zero findings.

## Key Constraints (Do Not Violate)
- **Read documentation**: Check RULES.md and TAXONOMY.md to understand naming conventions and design principles
- **YAML is valid**: DISSECT's strict parser already validated it. Only edit trait logic, not formatting.
- **Preserve structure**: Keep indentation, spacing, and file organization identical.
- **ID**: The trait ID should match the query parameters.
- **Confirm criticality**: Based on what the trait query, is the criticality appropriate or is it overblown?
- **Assume good intent**: You will find traits that are defined incorrectly, you can usually gather from the trait ID what the feature (benign or malicious) were trying to find.
- **Avoid unless/downgrade**: Only use these stanzas when it's not possible to improve the query to be more accurate or specific

{{.TaskBlock}}

## Success Criteria
✓ Malicious behavior is detected with appropriate trait IDs
✓ Detections use generic patterns (not file-specific signatures)
✓ Changes are minimal and focused
✓ Traits are correctly named after what they detect
✓ Traits have the correct criticality level for any kind of program that matches
✓ If a suspicious trait isn't genuinely suspicious, lower the criticality to notable.
✓ Improved thresholds - make traits as focused and specific as possible to meet their description
✓ Run dissect again - shows improvement

## Debug & Validate
` + "```" + `
{{.DissectBin}} {{.Path}} --format jsonl                   # see current findings
{{.DissectBin}} strings {{.Path}}                          # reveal XOR/AES/base64 hidden data
{{.DissectBin}} test-rules {{.Path}} --rules "rule-id"     # debug single rule
{{.DissectBin}} test-match {{.Path}} --type string --pattern "X"  # test patterns
` + "```" + `

Traits: {{.TraitsDir}}`))

var badPromptTmpl = template.Must(template.New("bad").Parse(`{{if .IsArchive -}}
# Add Missing Detection for KNOWN-BAD Files

**Source**: {{.ArchiveName}}
**Files**: {{.Count}} not flagged as suspicious/hostile
**Task**: Detect malicious behavior

## Top Files to Analyze (by size/complexity)
{{range .Files}}- {{.Path}}{{if .Summary}} ({{.Summary}}){{end}}
{{end}}
*Note: Skip genuinely benign files (README, docs, unmodified dependencies)*
{{else -}}
# Add Missing Detection for KNOWN-BAD File

**File**: {{.Path}}
**Problem**: Not flagged as suspicious/hostile
**Task**: Detect malicious behavior

*Note: Skip if genuinely benign (README, docs, unmodified dependency)*
{{end}}
## Key Constraints (Do Not Violate)
- **Read documentation**: Check RULES.md and TAXONOMY.md to understand naming conventions and design principles
- **YAML is valid**: DISSECT's strict parser already validated it. Only edit trait logic, not formatting.
- **Preserve structure**: Keep indentation, spacing, and file organization identical.
- **No new files**: Only modify existing traits/ YAML files.
- **One fix per trait**: Don't over-engineer; each trait should do one thing well.

{{.TaskBlock}}

## Success Criteria
✓ Malicious behavior is detected with appropriate trait IDs
✓ Detections use generic patterns (not file-specific signatures)
✓ Changes are minimal and focused
✓ Traits are correctly named after what they detect
✓ Traits have the correct criticality level for any kind of program that matches
✓ Run dissect again - shows improvement

## Debug & Validate
` + "```" + `
{{.DissectBin}} {{.Path}} --format jsonl                   # see current findings
{{.DissectBin}} strings {{.Path}}                          # reveal XOR/AES/base64 hidden data
{{.DissectBin}} test-rules {{.Path}} --rules "rule-id"     # debug single rule
{{.DissectBin}} test-match {{.Path}} --type string --pattern "X"  # test patterns
` + "```" + `

Traits: {{.TraitsDir}}`))

const goodTaskFile = `## Strategy: Fix False Positives
Review findings and identify which are actually false positives (incorrect matches).
Keep findings that accurately describe the code's behavior, even if suspicious.

**Priority Order** (try in this order):
1. **Taxonomy**: Trait ID doesn't match detected behavior? Fix it:
   - obj/c2/ should only detect C2 (beacon, command channels, reverse shells)
   - obj/exfil/ should only detect exfiltration (data collection + upload)
   - Simple HTTP/socket → cap/comm/, not obj/c2/ or obj/exfil/
   - Generic crypto → cap/crypto/, not obj/anti-static/
2. **Patterns**: Too broad? Refine the pattern itself to be more accurate:
   - ` + "`near: 200`" + ` - require proximity to suspicious code
   - ` + "`size_min/max`" + ` - filter by file size (legitimate: large, malware: compact)
   - ` + "`for: [elf, macho, pe]`" + ` - restrict to binaries (skip scripts)
   - ` + "`all:`" + ` in composites - combine weak signals into strong one
3. **Exclusions**: Known-good strings? Add ` + "`not:`" + ` filters to exclude them
4. **Reorganize**: Create new traits if it makes the logic clearer or more maintainable
5. **Downgrade**: Detection correct but criticality too high? Use ` + "`downgrade:`" + ` for specific cases
6. **Unless** (last resort): Only use ` + "`unless:`" + ` if fixing the pattern is impractical

**Taxonomy Verification**: Before modifying any trait, verify its ID accurately describes what it detects:
- Read TAXONOMY.md for the complete tier structure
- cap/ = observable capability (what code CAN do)
- obj/ = attacker objective (WHY code does something, requires combining capabilities)

**Prefer**: Fixing queries to be accurate over adding exceptions. If the detection IS correct but severity is wrong, use ` + "`downgrade:`" + ` instead of ` + "`unless:`" + `.

**If deleting or renaming a trait**: Update all references to it (in composites, depends, etc.). Consider what the composite trait was trying to accomplish and fix the reference appropriately.

**Do Not**: Change criticality levels arbitrarily, remove accurate findings, or break YAML structure.`

const goodTaskArchive = `## Strategy: Fix False Positives in Archive
Review findings and identify which are actually false positives (incorrect matches).
Keep findings that accurately describe the code's behavior, even if suspicious.

**Priority Order** (try in this order):
1. **Taxonomy**: Trait ID doesn't match detected behavior? Fix it:
   - obj/c2/ should only detect C2 (beacon, command channels, reverse shells)
   - obj/exfil/ should only detect exfiltration (data collection + upload)
   - Simple HTTP/socket → cap/comm/, not obj/c2/ or obj/exfil/
   - Generic crypto → cap/crypto/, not obj/anti-static/
2. **Patterns**: Too broad? Refine the pattern to be more accurate:
   - ` + "`near: 200`" + ` - require proximity to suspicious code
   - ` + "`size_min/max`" + ` - legitimate installers are huge, malware is compact
   - ` + "`for: [elf, macho, pe]`" + ` - restrict to binaries only
   - ` + "`all:`" + ` in composites - combine weak signals, don't flag individually
3. **Exclusions**: Known-good strings? Add ` + "`not:`" + ` filters to exclude them
4. **Reorganize**: Create new traits if it makes the logic clearer or more maintainable
5. **Adjust criticality**: Is the criticality generally incorrect for what the search term matches? Adjust it.
5. **Downgrade**: Detection correct but criticality too high for this specific unusual case? Use ` + "`downgrade:`" + ` for specific cases

**Taxonomy Verification**: Before modifying any trait, verify its ID accurately describes what it detects:
- Read TAXONOMY.md for the complete tier structure
- cap/ = observable capability (what code CAN do)
- obj/ = attacker objective (WHY code does something, requires combining capabilities)

**Prefer**: Fixing traits to be accurately defined over adding exceptions. If the detection IS generally correct but criticality is wrong for this specific unusual case, use the downgrade: stanza

**If deleting or renaming a trait**: Update all references to it (in composites, depends, etc.). Consider what the composite trait was trying to accomplish and fix the reference appropriately.

**Do Not**: Change criticality levels arbitrarily, remove accurate findings, or break YAML structure.`

const badTaskFile = `## Strategy: Add Missing Detection
**Approach**:
1. Reverse engineer the file (strings, radare2, nm, objdump)
   - **Use ` + "`dissect strings`" + `** to automatically reveal hidden data: XOR/AES/base64 encoded payloads, command strings, and obfuscated content
   - This exposes both encoded and decoded content for better pattern matching
2. Identify malicious capability (socket + exec = reverse-shell, etc.)
3. Identify ALL unique and interesting features of this program:
   - Unusual techniques or methods (e.g., process hollowing, DLL sideloading)
   - Distinctive strings, constants, or magic values
   - Uncommon library usage or API call patterns
   - Novel obfuscation or evasion techniques
   - Any behavior that distinguishes this from typical software
4. Use GENERIC patterns, not file-specific signatures
5. Cross-language when possible (base64+exec works in Python, JS, Shell)
6. Create new traits if needed - they should be generic and reusable across samples

## Taxonomy Rules (MUST FOLLOW)
**Read TAXONOMY.md first** - trait IDs must accurately describe what the pattern detects.

- **cap/** = Observable capability (what code CAN do) - single pattern, value-neutral
  - cap/comm/ = network communication (socket, http, dns)
  - cap/exec/ = code execution (shell, eval)
  - cap/crypto/ = cryptographic operations
  - cap/fs/ = filesystem operations

- **obj/** = Attacker objective (WHY code does something) - composites combining caps
  - obj/c2/ = Command & control: beacon patterns, command channels, reverse shells
  - obj/exfil/ = Data exfiltration: data collection + upload to attacker
  - obj/persist/ = Persistence: startup entries, services, scheduled tasks
  - obj/creds/ = Credential theft: browser passwords, system credentials
  - obj/anti-static/ = Anti-analysis: obfuscation, packing, VM detection

- **known/** = ONLY for specific malware families (apt/cozy-bear, trojan/emotet)

**CRITICAL**: Verify the trait ID matches detected behavior:
- Simple HTTP request → cap/comm/http/ (NOT obj/c2/ or obj/exfil/)
- C2 requires: beacon intervals, command parsing, or bidirectional control channel
- Exfil requires: data collection (files, creds, keys) + upload mechanism
- Don't put generic network/crypto in obj/ - that's what cap/ is for

**If deleting or renaming a trait**: Update all references to it (in composites, depends, etc.). Consider what the composite trait was trying to accomplish and fix the reference appropriately.

**Do Not**: Create file-specific rules, put capabilities in obj/, or ignore taxonomy structure.`

const badTaskArchive = `## Strategy: Add Missing Detection to Archive
**Approach**:
1. For each problematic member: reverse engineer (strings, radare2, nm, objdump)
   - **Use ` + "`dissect strings`" + ` on suspicious members** to reveal hidden data: XOR/AES/base64 encoded payloads, command strings, and obfuscated content
   - This exposes both encoded and decoded content for better pattern matching
2. Identify malicious capability (socket + exec = reverse-shell, etc.)
3. Identify ALL unique and interesting features of these programs:
   - Unusual techniques or methods (e.g., process hollowing, DLL sideloading)
   - Distinctive strings, constants, or magic values
   - Uncommon library usage or API call patterns
   - Novel obfuscation or evasion techniques
   - Any behavior that distinguishes this from typical software
4. Use GENERIC patterns, not file-specific signatures
5. Cross-language patterns when possible (base64+exec in Python, JS, Shell)
6. Create new traits if needed - they should be generic and reusable across samples

## Taxonomy Rules (MUST FOLLOW)
**Read TAXONOMY.md first** - trait IDs must accurately describe what the pattern detects.

- **cap/** = Observable capability (what code CAN do) - single pattern, value-neutral
  - cap/comm/ = network communication (socket, http, dns)
  - cap/exec/ = code execution (shell, eval)
  - cap/crypto/ = cryptographic operations
  - cap/fs/ = filesystem operations

- **obj/** = Attacker objective (WHY code does something) - composites combining caps
  - obj/c2/ = Command & control: beacon patterns, command channels, reverse shells
  - obj/exfil/ = Data exfiltration: data collection + upload to attacker
  - obj/persist/ = Persistence: startup entries, services, scheduled tasks
  - obj/creds/ = Credential theft: browser passwords, system credentials
  - obj/anti-static/ = Anti-analysis: obfuscation, packing, VM detection

- **known/** = ONLY for specific malware families (apt/cozy-bear, trojan/emotet)

**CRITICAL**: Verify the trait ID matches detected behavior:
- Simple HTTP request → cap/comm/http/ (NOT obj/c2/ or obj/exfil/)
- C2 requires: beacon intervals, command parsing, or bidirectional control channel
- Exfil requires: data collection (files, creds, keys) + upload mechanism
- Don't put generic network/crypto in obj/ - that's what cap/ is for

**If deleting or renaming a trait**: Update all references to it (in composites, depends, etc.). Consider what the composite trait was trying to accomplish and fix the reference appropriately.

**Do Not**: Create file-specific rules, put capabilities in obj/, or ignore taxonomy structure.`

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
	dissectBin  string // Path to dissect binary
	provider    string
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

// archiveNeedsReview returns true if any member of the archive needs review.
// For known-good archives: review if ANY member is flagged (to reduce false positives).
// For known-bad archives: review if NO members are detected yet (once 1 member is detected, archive is done).
func archiveNeedsReview(a *ArchiveAnalysis, knownGood bool) bool {
	if knownGood {
		// Known-good: review if ANY member has findings
		for _, m := range a.Members {
			if needsReview(m, knownGood) {
				return true
			}
		}
		return false
	}
	// Known-bad: review only if ALL members are undetected (archive is done once any member detected)
	for _, m := range a.Members {
		if !needsReview(m, knownGood) {
			// Found a member with findings - archive is already flagged, skip it
			return false
		}
	}
	// All members are undetected - archive needs review
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
	provider := flag.String("provider", "claude", "AI provider: claude, gemini, codex, or opencode")
	model := flag.String("model", "", `Model to use (provider-specific). Popular choices:
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

	*provider = strings.ToLower(*provider)
	if *provider != "claude" && *provider != "gemini" && *provider != "codex" && *provider != "opencode" {
		log.Fatalf("Unknown provider %q: must be claude, gemini, codex, or opencode", *provider)
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
	// DISSECT writes files to <extract-dir>/<sha256>/<relative-path>.
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
		provider:    *provider,
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

	if cfg.model != "" {
		fmt.Fprintf(os.Stderr, "Provider: %s (model: %s)\n", cfg.provider, cfg.model)
	} else {
		fmt.Fprintf(os.Stderr, "Provider: %s\n", cfg.provider)
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
	fmt.Fprintf(os.Stderr, "   [repair] Submitting YAML-only fix task to %s\n", cfg.provider)

	prompt := buildYAMLTraitFixPrompt(cfg, phase, failureOutput)
	sid := generateSessionID()

	tctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	if err := runAIWithStreaming(tctx, cfg, prompt, sid); err != nil {
		return err
	}
	return nil
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
	fmt.Fprintf(os.Stderr, ">>> %s working (timeout: %s)...\n", cfg.provider, cfg.timeout)
	fmt.Fprintln(os.Stderr)

	tctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, ">>> About to start AI process with timeout %s\n", cfg.timeout)
	if err := runAIWithStreaming(tctx, cfg, prompt, sid); err != nil {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "<<< %s failed: %v\n", cfg.provider, err)
		return err
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "<<< %s finished successfully\n", cfg.provider)
	return nil
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
	fmt.Fprintf(os.Stderr, ">>> %s working (timeout: %s)...\n", cfg.provider, cfg.timeout)
	fmt.Fprintln(os.Stderr)

	tctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, ">>> About to start AI process with timeout %s\n", cfg.timeout)
	err := runAIWithStreaming(tctx, cfg, prompt, sid)
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

	// Build command args (prompt sent via stdin)
	switch cfg.provider {
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
			"--resume", "latest",
			"--include-directories", cfg.repoRoot,
			"--include-directories", cfg.extractDir,
		}
		if home, err := os.UserHomeDir(); err == nil {
			args = append(args, "--include-directories", filepath.Join(home, "data"))
		}
		if cfg.model != "" {
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
