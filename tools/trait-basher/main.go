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
	"text/template"
	"time"

	"github.com/creack/pty"
	_ "github.com/mattn/go-sqlite3"
)

// promptData holds values for prompt templates.
type promptData struct {
	Path       string
	DissectBin string
	TraitsDir  string
	TaskBlock  string
	Count      int
	IsArchive  bool
}

var goodPromptTmpl = template.Must(template.New("good").Parse(`{{if .IsArchive -}}
# Fix False Positives in KNOWN-GOOD Archive

**Archive**: {{.Path}}
**Problem**: {{.Count}} members flagged as suspicious/hostile
**Task**: Remove false positive findings
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

**Expected**: Known-good software has findings! Notable and suspicious findings are normal if they accurately describe what the code does. The goal is ACCURATE findings, not zero findings.

## Key Constraints (Do Not Violate)
- **Read documentation**: Check RULES.md and TAXONOMY.md to understand naming conventions and design principles
- **YAML is valid**: DISSECT's strict parser already validated it. Only edit trait logic, not formatting.
- **Preserve structure**: Keep indentation, spacing, and file organization identical.
- **No new files**: Only modify existing traits/ YAML files.
- **One fix per trait**: Don't over-engineer; each trait should do one thing well.

{{.TaskBlock}}

## Success Criteria
✓ All false positive findings are fixed (incorrect matches removed or constrained)
✓ Remaining findings accurately describe what the program actually does
✓ No new false positives introduced
✓ Changes are minimal and focused (3-5 edits max)
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
# Add Missing Detection for KNOWN-BAD Archive

**Archive**: {{.Path}}
**Problem**: {{.Count}} members not flagged as suspicious/hostile
**Task**: Detect malicious behavior

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
✓ All false positive findings are fixed (incorrect matches removed or constrained)
✓ Remaining findings accurately describe what the program actually does
✓ No new false positives introduced
✓ Changes are minimal and focused (3-5 edits max)
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

const goodTaskArchive = `## Strategy: Fix False Positives in Archive
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

const badTaskFile = `## Strategy: Add Missing Detection
**Approach**:
1. Reverse engineer the file (strings, radare2, nm, objdump)
   - **Use ` + "`dissect strings`" + `** to automatically reveal hidden data: XOR/AES/base64 encoded payloads, command strings, and obfuscated content
   - This exposes both encoded and decoded content for better pattern matching
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

const badTaskArchive = `## Strategy: Add Missing Detection to Archive
**Approach**:
1. For each problematic member: reverse engineer (strings, radare2, nm, objdump)
   - **Use ` + "`dissect strings`" + ` on suspicious members** to reveal hidden data: XOR/AES/base64 encoded payloads, command strings, and obfuscated content
   - This exposes both encoded and decoded content for better pattern matching
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

func buildGoodPrompt(isArchive bool, path string, count int, root, bin string) string {
	task := goodTaskFile
	if isArchive {
		task = goodTaskArchive
	}
	var b bytes.Buffer
	_ = goodPromptTmpl.Execute(&b, promptData{ //nolint:errcheck // template is validated at init
		Path:       path,
		Count:      count,
		DissectBin: bin,
		TraitsDir:  root + "/traits/",
		IsArchive:  isArchive,
		TaskBlock:  task,
	})
	return b.String()
}

func buildBadPrompt(isArchive bool, path string, count int, root, bin string) string {
	task := badTaskFile
	if isArchive {
		task = badTaskArchive
	}
	var b bytes.Buffer
	_ = badPromptTmpl.Execute(&b, promptData{ //nolint:errcheck // template is validated at init
		Path:       path,
		Count:      count,
		DissectBin: bin,
		TraitsDir:  root + "/traits/",
		IsArchive:  isArchive,
		TaskBlock:  task,
	})
	return b.String()
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
	idleTimeout time.Duration // Kill LLM if no output for this duration
	rescanAfter int           // Number of files to review before restarting scan (0 = disabled)
	knownGood   bool
	knownBad    bool
	useCargo    bool
	flush       bool
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
// Supports: .zip, .tar, .tar.gz, .tgz, .7z, .xz.
func extractArchive(ctx context.Context, archivePath, destDir string) (*archiveExtraction, error) {
	fmt.Fprintf(os.Stderr, "  [debug] extractArchive: %s -> %s\n", archivePath, destDir)

	ext := strings.ToLower(filepath.Ext(archivePath))

	// Check for compound extensions
	base := strings.ToLower(filepath.Base(archivePath))
	if strings.HasSuffix(base, ".tar.gz") || strings.HasSuffix(base, ".tgz") {
		ext = ".tar.gz"
	}

	fmt.Fprintf(os.Stderr, "  [debug] Detected archive format: %s\n", ext)

	switch ext {
	case ".zip":
		return extractZip(ctx, archivePath, destDir)
	case ".tar":
		return extractTar(archivePath, destDir)
	case ".tar.gz", ".tgz":
		return extractTarGz(archivePath, destDir)
	case ".7z":
		return extract7zWithPasswords(ctx, archivePath, destDir, []string{"infected", "infect3d"})
	case ".xz":
		return extractXz(ctx, archivePath, destDir)
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", ext)
	}
}

// isZipEncrypted checks if a ZIP archive is encrypted by examining the file headers.
func isZipEncrypted(archivePath string) bool {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		// If we can't open it, assume encrypted to trigger password attempts
		fmt.Fprintf(os.Stderr, "  [debug] Failed to open ZIP for encryption check: %v\n", err)
		return true
	}
	defer reader.Close() //nolint:errcheck // best-effort cleanup

	// Check first file's encryption flag (bit 0 of Flags field)
	if len(reader.File) > 0 {
		encrypted := reader.File[0].Flags&0x1 != 0
		fmt.Fprintf(os.Stderr, "  [debug] ZIP has %d files, first file encrypted flag: %v\n", len(reader.File), encrypted)
		return encrypted
	}
	fmt.Fprintf(os.Stderr, "  [debug] ZIP is empty\n")
	return false
}

// Common malware archive passwords to try.
var defaultPasswords = []string{"infected", "infect3d", "malware", "virus", "password"}

// critRank maps criticality levels to numeric ranks for comparison.
var critRank = map[string]int{"inert": 0, "notable": 1, "suspicious": 2, "hostile": 3}

// extract7zWithPasswords extracts an archive using 7z with password attempts.
func extract7zWithPasswords(ctx context.Context, src, dst string, passwords []string) (*archiveExtraction, error) {
	var lastErr error
	for i, pwd := range passwords {
		fmt.Fprintf(os.Stderr, "  [debug] Trying password %d/%d: %s\n", i+1, len(passwords), pwd)

		tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		cmd := exec.CommandContext(tctx, "7z", "x", "-o"+dst, "-y", "-p"+pwd, src) //nolint:gosec // paths come from controlled archive extraction
		cmd.Stdin = nil                                                            // Don't wait for user input

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err == nil {
			cancel()
			members, err := listDir(dst)
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(os.Stderr, "  [debug] 7z extraction succeeded with password: %s\n", pwd)
			return &archiveExtraction{path: dst, members: members}, nil
		}
		cancel()
		lastErr = errors.New(stderr.String())
		fmt.Fprintf(os.Stderr, "  [debug] 7z password attempt failed: %s\n", stderr.String())
	}
	if lastErr != nil {
		return nil, fmt.Errorf("7z extraction failed (tried %d passwords): %w", len(passwords), lastErr)
	}
	return nil, errors.New("7z extraction failed")
}

// extractZip extracts a ZIP archive.
func extractZip(ctx context.Context, src, dst string) (*archiveExtraction, error) {
	fmt.Fprintf(os.Stderr, "  [debug] extractZip called for: %s\n", src)
	if isZipEncrypted(src) {
		fmt.Fprintf(os.Stderr, "  [debug] Archive appears encrypted, using password-based extraction\n")
		return extract7zWithPasswords(ctx, src, dst, defaultPasswords)
	}
	fmt.Fprintf(os.Stderr, "  [debug] Archive appears unencrypted, using standard Go ZIP extraction\n")

	r, err := zip.OpenReader(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [debug] Failed to open ZIP reader: %v\n", err)
		fmt.Fprintf(os.Stderr, "  [debug] Falling back to 7z extraction for potentially corrupted ZIP\n")
		return extract7zWithPasswords(ctx, src, dst, defaultPasswords)
	}
	defer r.Close() //nolint:errcheck // best-effort cleanup

	fmt.Fprintf(os.Stderr, "  [debug] ZIP reader opened, processing %d files\n", len(r.File))

	var members []string
	for i, zf := range r.File {
		// Prevent zip slip: ensure extracted path stays within destination
		p := filepath.Join(dst, zf.Name) //nolint:gosec // validated by HasPrefix check below
		if !strings.HasPrefix(filepath.Clean(p), filepath.Clean(dst)+string(os.PathSeparator)) {
			fmt.Fprintf(os.Stderr, "  [debug] Skipping unsafe path: %s\n", zf.Name)
			continue
		}
		fmt.Fprintf(os.Stderr, "  [debug] Processing file %d/%d: %s (encrypted: %v)\n", i+1, len(r.File), zf.Name, zf.Flags&0x1 != 0)

		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(p, 0o750); err != nil {
				return nil, fmt.Errorf("create directory: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return nil, fmt.Errorf("create directory: %w", err)
		}

		rc, err := zf.Open()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [debug] Failed to open file in ZIP: %v\n", err)
			return nil, fmt.Errorf("open file in zip: %w", err)
		}

		f, err := os.Create(p)
		if err != nil {
			rc.Close() //nolint:errcheck,gosec // best-effort cleanup on error
			return nil, fmt.Errorf("create extracted file: %w", err)
		}

		if _, err := io.Copy(f, rc); err != nil { //nolint:gosec // decompression bomb acceptable for malware analysis
			fmt.Fprintf(os.Stderr, "  [debug] Failed to copy file data for %s: %v\n", zf.Name, err)
			rc.Close() //nolint:errcheck,gosec // best-effort cleanup on error
			f.Close()  //nolint:errcheck,gosec // best-effort cleanup on error
			fmt.Fprintf(os.Stderr, "  [debug] Falling back to 7z due to file extraction error\n")
			return extract7zWithPasswords(ctx, src, dst, defaultPasswords)
		}
		rc.Close() //nolint:errcheck,gosec // best-effort cleanup
		f.Close()  //nolint:errcheck,gosec // best-effort cleanup

		members = append(members, zf.Name)
	}

	fmt.Fprintf(os.Stderr, "  [debug] Successfully extracted %d files with standard ZIP extraction\n", len(members))
	return &archiveExtraction{path: dst, members: members}, nil
}

// extractTar extracts a plain TAR archive.
func extractTar(src, dst string) (*archiveExtraction, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, fmt.Errorf("open tar: %w", err)
	}
	defer f.Close() //nolint:errcheck // best-effort cleanup
	return extractTarReader(tar.NewReader(f), dst)
}

// extractTarGz extracts a tar.gz archive.
func extractTarGz(src, dst string) (*archiveExtraction, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, fmt.Errorf("open tar.gz: %w", err)
	}
	defer f.Close() //nolint:errcheck // best-effort cleanup

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %w", err)
	}
	defer gr.Close() //nolint:errcheck // best-effort cleanup

	return extractTarReader(tar.NewReader(gr), dst)
}

func extractTarReader(tr *tar.Reader, dst string) (*archiveExtraction, error) {
	var members []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}

		// Prevent path traversal: ensure extracted path stays within destination
		p := filepath.Join(dst, hdr.Name) //nolint:gosec // validated by HasPrefix check below
		if !strings.HasPrefix(filepath.Clean(p), filepath.Clean(dst)+string(os.PathSeparator)) {
			fmt.Fprintf(os.Stderr, "  [debug] Skipping unsafe path: %s\n", hdr.Name)
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o750); err != nil {
				return nil, fmt.Errorf("create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				return nil, fmt.Errorf("create directory: %w", err)
			}
			f, err := os.Create(p)
			if err != nil {
				return nil, fmt.Errorf("create extracted file: %w", err)
			}
			if _, err := io.CopyN(f, tr, hdr.Size); err != nil {
				f.Close() //nolint:errcheck,gosec // best-effort cleanup on error
				return nil, fmt.Errorf("extract file: %w", err)
			}
			f.Close() //nolint:errcheck,gosec // best-effort cleanup
			members = append(members, hdr.Name)
		}
	}
	return &archiveExtraction{path: dst, members: members}, nil
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
	defer out.Close() //nolint:errcheck // best-effort cleanup

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
			fmt.Fprintf(os.Stderr, "  [debug] listDir walk error at %s: %v\n", path, err)
			return err
		}
		if !info.IsDir() {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			files = append(files, rel)
			fmt.Fprintf(os.Stderr, "  [debug] Found file: %s (size: %d bytes)\n", rel, info.Size())
		}
		return nil
	})
	return files, err
}

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
	provider := flag.String("provider", "claude", "AI provider: claude, gemini, or opencode")
	model := flag.String("model", "", `Model to use (provider-specific). Popular choices:
  claude:   sonnet, opus, haiku
  gemini:   gemini-3-pro-preview, gemini-3-flash-preview,
            gemini-2.5-pro, gemini-2.5-flash, gemini-2.5-flash-lite
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
		idleTimeout: *idleTimeout,
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
	fmt.Fprintf(os.Stderr, "LLM timeout: %v (session max), %v (idle)\n", cfg.timeout, cfg.idleTimeout)
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
	filesReviewedCount int // Count of files sent to LLM for review
}

// streamAnalyzeAndReview streams dissect output and reviews archives as they complete.
func streamAnalyzeAndReview(ctx context.Context, cfg *config, dbMode string) (*streamStats, error) {
	// Build dissect command
	maxRisk := "notable"
	if cfg.knownGood {
		maxRisk = "hostile"
	}
	args := []string{"--format", "jsonl", "--sample-dir", cfg.sampleDir, "--sample-max-risk", maxRisk}
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

	if !archiveNeedsReview(a, st.cfg.knownGood) {
		mode := "bad"
		if st.cfg.knownGood {
			mode = "good"
		}
		fmt.Fprintf(os.Stderr, "  [skip] Archive %s (--%-4s): no members need review\n", filepath.Base(a.ArchivePath), mode)
		st.stats.skippedNoReview++
		return
	}

	h := hashString(a.ArchivePath)
	if wasAnalyzed(ctx, st.cfg.db, h, st.dbMode) {
		fmt.Fprintf(os.Stderr, "  [skip] Archive %s: already analyzed (cache hit)\n", filepath.Base(a.ArchivePath))
		st.stats.skippedCached++
		return
	}

	prob := archiveProblematicMembers(a, st.cfg.knownGood)
	skip := len(a.Members) - len(prob)
	fmt.Fprintf(os.Stderr, "\n📦 Archive complete: %s\n", a.ArchivePath)
	fmt.Fprintf(os.Stderr, "   Members: %d total, %d need review, %d filtered\n", len(a.Members), len(prob), skip)

	// Log which members were filtered out
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
				fmt.Fprintf(os.Stderr, "      - %s (%s): not critical enough\n", memberPath(m.Path), strings.TrimSpace(crits))
			}
		}
	}

	fmt.Fprintf(os.Stderr, "   Members requiring review:\n")
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
		fmt.Fprintf(os.Stderr, "   - %s (%s)\n", memberPath(m.Path), strings.Join(parts, ", "))
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
		if st.cfg.knownGood {
			mode = "good"
		}
		fmt.Fprintf(os.Stderr, "  [skip] File %s (--%-4s): no suspicious/hostile findings\n", filepath.Base(rf.RealPath), mode)
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

	fmt.Fprintf(os.Stderr, ">>> Preparing to invoke %s for archive (session: %s)\n", cfg.provider, sid)
	fmt.Fprintf(os.Stderr, ">>> Archive: %s (%d members, %d problematic)\n", a.ArchivePath, len(a.Members), len(prob))

	// Extract archive (full for --bad, problematic files only for --good)
	dir, err := os.MkdirTemp("", "trait-basher-archive-*")
	if err != nil {
		return fmt.Errorf("create extract directory: %w", err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck,gosec // best-effort cleanup of temp directory

	var info string

	if cfg.knownBad {
		// --bad mode: extract full archive for comprehensive analysis
		fmt.Fprintf(os.Stderr, "  [debug] Starting full archive extraction for --bad mode\n")
		ext, err := extractArchive(ctx, a.ArchivePath, dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [debug] Archive extraction failed: %v\n", err)
			return fmt.Errorf("extract archive: %w", err)
		}
		fmt.Fprintf(os.Stderr, "  [debug] Archive extraction succeeded, %d members extracted\n", len(ext.members))

		notable, largest := archiveMemberStats(a)
		var hints []string
		if notable != nil {
			hints = append(hints, fmt.Sprintf("Most notable findings in: %s", memberPath(notable.Path)))
		}
		if largest != nil {
			hints = append(hints, fmt.Sprintf("Largest file: %s", memberPath(largest.Path)))
		}

		info = fmt.Sprintf("\n\n## Extracted Archive\nFull archive extracted to: %s\n"+
			"You can now read the actual source code to understand the malicious behavior.\n", dir)
		if len(hints) > 0 {
			info += "Hints for investigation:\n"
			for _, h := range hints {
				info += fmt.Sprintf("- %s\n", h)
			}
		}
		info += "After analyzing, update the rules in traits/ to detect the malicious behavior found."
	} else {
		// --good mode: extract only problematic files
		dir2, err := os.MkdirTemp("", "trait-basher-problematic-*")
		if err != nil {
			return fmt.Errorf("create problematic extract directory: %w", err)
		}
		defer os.RemoveAll(dir2) //nolint:errcheck,gosec // best-effort cleanup of temp directory

		for _, m := range prob {
			if m.ExtractedPath == "" {
				continue
			}
			dst := filepath.Join(dir2, filepath.Base(m.Path))
			if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
				return fmt.Errorf("create directory: %w", err)
			}
			sf, err := os.Open(m.ExtractedPath)
			if err != nil {
				return fmt.Errorf("open extracted file %s: %w", m.ExtractedPath, err)
			}
			df, err := os.Create(dst)
			if err != nil {
				sf.Close() //nolint:errcheck,gosec // best-effort cleanup on error
				return fmt.Errorf("create destination file: %w", err)
			}
			if _, err := io.Copy(df, sf); err != nil {
				sf.Close() //nolint:errcheck,gosec // best-effort cleanup on error
				df.Close() //nolint:errcheck,gosec // best-effort cleanup on error
				return fmt.Errorf("copy extracted file: %w", err)
			}
			sf.Close() //nolint:errcheck,gosec // best-effort cleanup
			df.Close() //nolint:errcheck,gosec // best-effort cleanup
		}

		info = fmt.Sprintf("\n\n## Problematic Files\nFalse positive files extracted to: %s\n"+
			"Review these files to understand why they're being incorrectly flagged.\n"+
			"Adjust the rules in traits/ to fix the false positives.", dir2)
	}

	var prompt, task string
	if cfg.knownGood {
		prompt = buildGoodPrompt(true, a.ArchivePath, len(prob), cfg.repoRoot, cfg.dissectBin)
		task = "Review archive for false positives (known-good collection)"
	} else {
		prompt = buildBadPrompt(true, a.ArchivePath, len(prob), cfg.repoRoot, cfg.dissectBin)
		task = "Find missing detections in archive (known-bad collection)"
	}

	prompt += info

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

	// Still include extracted binary samples if available
	if cfg.knownGood && len(prob) > 0 {
		var paths []string
		for _, m := range prob {
			if m.ExtractedPath != "" {
				paths = append(paths, fmt.Sprintf("- %s", m.ExtractedPath))
			}
		}
		if len(paths) > 0 {
			prompt += fmt.Sprintf("\nBinary analysis tools available at: %s\n%s",
				cfg.sampleDir, strings.Join(paths, "\n"))
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
	fmt.Fprintf(os.Stderr, "│ %s ARCHIVE REVIEW: %s\n", strings.ToUpper(cfg.provider), a.ArchivePath)
	fmt.Fprintf(os.Stderr, "│ Members: %d total, %d problematic\n", len(a.Members), len(prob))
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
	err = runAIWithStreaming(tctx, cfg, prompt, sid)
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

	// Use PTY to force line-buffered output from the child process.
	// Many CLIs switch to block-buffered output when stdout is a pipe,
	// causing output to appear hung. PTY makes the CLI think it's
	// connected to a terminal, forcing immediate output.
	fmt.Fprintf(os.Stderr, ">>> Starting process with PTY...\n")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("could not start %s with pty: %w", cfg.provider, err)
	}
	defer ptmx.Close() //nolint:errcheck // best-effort cleanup
	fmt.Fprintf(os.Stderr, ">>> Process started (PID: %d)\n", cmd.Process.Pid)

	var (
		output     []string
		outputMu   sync.Mutex
		lastActive = time.Now()
		activeMu   sync.Mutex
	)
	done := make(chan struct{})

	// PTY combines stdout and stderr into a single stream
	go func() {
		sc := bufio.NewScanner(ptmx)
		n := 0
		for sc.Scan() {
			ln := sc.Text()
			n++
			displayStreamEvent(ln)
			outputMu.Lock()
			output = append(output, ln)
			outputMu.Unlock()
			activeMu.Lock()
			lastActive = time.Now()
			activeMu.Unlock()
		}
		fmt.Fprintf(os.Stderr, ">>> PTY closed after %d lines\n", n)
		done <- struct{}{}
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			fmt.Fprintf(os.Stderr, ">>> Stream finished\n")
			goto waitForExit
		case <-ticker.C:
			if cmd.ProcessState == nil {
				activeMu.Lock()
				idle := time.Since(lastActive)
				activeMu.Unlock()

				if idle > cfg.idleTimeout {
					fmt.Fprintf(os.Stderr, "\n>>> [idle timeout] No output for %v, killing process...\n", cfg.idleTimeout)
					cmd.Process.Kill() //nolint:errcheck,gosec // best-effort kill on timeout
					fmt.Fprintf(os.Stderr, ">>> Process killed (PID: %d)\n", cmd.Process.Pid)
					return fmt.Errorf("idle timeout: no output for %v", cfg.idleTimeout)
				}

				fmt.Fprintf(os.Stderr, ">>> Still running (PID: %d, idle: %v, timeout remaining: %s)\n",
					cmd.Process.Pid, idle.Round(time.Second), timeRemaining(ctx))
			}
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "\n>>> [timeout] timed out, killing process...")
			cmd.Process.Kill() //nolint:errcheck,gosec // best-effort kill on timeout
			fmt.Fprintf(os.Stderr, ">>> Process killed (PID: %d)\n", cmd.Process.Pid)
			return fmt.Errorf("timeout: %w", ctx.Err())
		}
	}
waitForExit:

	fmt.Fprintf(os.Stderr, ">>> Waiting for process to exit...\n")
	err = cmd.Wait()
	exitCode := cmd.ProcessState.ExitCode()
	fmt.Fprintf(os.Stderr, ">>> Process exited with code %d\n", exitCode)

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errors.New("exceeded time limit")
		}
		outputMu.Lock()
		all := strings.Join(output, "\n")
		outputMu.Unlock()

		var b strings.Builder
		fmt.Fprintf(&b, "%s exited with code %d\n\n", cfg.provider, exitCode)
		fmt.Fprintf(&b, "Command: %s %s\n", cmd.Path, strings.Join(cmd.Args[1:], " "))
		fmt.Fprintf(&b, "Working directory: %s\n", cmd.Dir)
		if all != "" {
			fmt.Fprintf(&b, "\nFull output:\n%s\n", all)
		} else {
			b.WriteString("\n(no output)\n")
		}
		fmt.Fprintf(os.Stderr, "\n>>> %s\n", b.String())
		return errors.New(b.String())
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
