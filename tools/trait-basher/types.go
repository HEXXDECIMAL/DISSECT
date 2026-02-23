package main

import (
	"database/sql"
	"sync"
	"time"
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
	Path                  string      // Primary file path (extracted dir for archives, file path for standalone)
	ArchiveName           string      // Archive basename for context (empty for standalone)
	Files                 []fileEntry // Top files with findings (sorted by severity)
	DissectBin            string
	TraitsDir             string
	Count                 int
	IsArchive             bool
	IsBad                 bool   // true for known-bad mode, false for known-good mode
	ReportExists          bool   // For bad files: true if research report already exists
	ReportPath            string // Path to research report (bad files)
	GapAnalysisPath       string // Path to gap analysis (bad files)
	RelatedBadReportPath  string // For good files: path to report if file exists in bad collection
	HasRelatedBadReport   bool   // For good files: true if file exists in bad collection
	BenignMarkerPath      string // Path where ._<filename>.BENIGN marker would be created
	BadMarkerPath         string // Path where ._<filename>.BAD marker would be created
	MayBeBenign           bool   // For bad files: suggest checking if it's actually benign
	MayBeBad              bool   // For good files: suggest checking if it's actually bad
	HasHostileFindings    bool   // For good files: has hostile findings that need fixing
	HasSuspiciousFindings bool   // For good files: has suspicious findings to review
	IsValidationSample    bool   // True when file was randomly selected for validation (passed normal thresholds)
}

// config holds all configuration for a trait-basher session.
type config struct {
	db            *sql.DB
	dirs          []string
	repoRoot      string
	dissectBin    string   // Path to dissect binary
	providers     []string // Ordered list of providers to try (fallback on failure)
	provider      string   // Current active provider (set during invocation)
	model         string
	extractDir    string // Directory where DISSECT extracts files
	timeout       time.Duration
	idleTimeout   time.Duration // Kill LLM if no output for this duration
	rescanAfter   int           // Number of files to review before restarting scan (0 = disabled)
	concurrency   int           // Number of concurrent LLM review sessions
	knownGood     bool
	knownBad      bool
	useCargo      bool
	flush         bool
	verbose       bool // Show detailed skip/progress messages
	validateEvery int  // Randomly validate 1 in N files even if properly classified (0 = disabled)
}

// reviewJob represents a file or archive to be reviewed by an LLM.
type reviewJob struct {
	archive      *ArchiveAnalysis  // non-nil for archive reviews
	file         *RealFileAnalysis // non-nil for standalone file reviews
	isValidation bool              // true if this is a validation sample (randomly selected for audit)
}

// reviewResult contains the outcome of a review job.
type reviewResult struct {
	job      reviewJob
	err      error
	duration time.Duration
	provider string
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
type ArchiveAnalysis struct {
	ArchivePath     string
	Members         []FileAnalysis
	SummaryRisk     string    // Aggregated risk from archive summary entry
	SummaryFindings []Finding // Archive-level findings (zip-bomb, etc.)
}

// RealFileAnalysis groups a real file with all its encoded/decoded fragments.
type RealFileAnalysis struct {
	RealPath  string         // The real file path (stripped of ## fragment delimiters)
	Root      FileAnalysis   // The root/real file entry
	Fragments []FileAnalysis // All decoded fragment entries (if any)
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

// streamStats tracks streaming analysis statistics.
type streamStats struct {
	archivesReviewed     int
	standaloneReviewed   int
	skippedCached        int
	skippedNoReview      int
	totalFiles           int
	totalStandaloneFiles int           // Total standalone files seen (not in archives)
	reviewTimeTotal      time.Duration // Total time spent in LLM reviews
	shouldRestart        bool          // Set to true when rescan limit reached
	estimatedTotal       int           // Estimated total files (from pre-count)
	scanStartTime        time.Time     // When scanning started (for rate calculation)
	mu                   sync.Mutex    // Protects stats updated from result collector goroutine
}

// critRank maps criticality levels to numeric ranks for comparison.
var critRank = map[string]int{"inert": 0, "notable": 1, "suspicious": 2, "hostile": 3}

// workerState tracks the current state of a single LLM worker slot.
type workerState struct {
	busy         bool      // true if processing a job
	path         string    // current job path (empty if idle)
	provider     string    // current provider being used
	startTime    time.Time // when current job/idle started
	isValidation bool      // true if this is a validation sample (random audit)
}
