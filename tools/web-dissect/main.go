package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/buildkite/terminal-to-html"
)

var (
	uploadTemplate *template.Template
	resultTemplate *template.Template
	gcsBucket      string
	dissectPath    string
	rulesPath      string
	radare2Path    string
	rizinPath      string
	radareCmd      string // resolved backend: "radare2" or "rizin"
	radareCmdPath  string // resolved full path to backend
	logger         *slog.Logger
)

type resultData struct {
	Filename string
	SHA256   string
	Output   template.HTML
}

// toolInfo holds information about an external tool.
type toolInfo struct {
	name    string
	path    string
	version string
}

func init() {
	// Initialize structured logger with JSON output for production
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)
}

func main() {
	logger.Info("web-dissect starting",
		"go_version", runtime.Version(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"pid", os.Getpid(),
	)

	// Load configuration from environment
	if err := loadConfig(); err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}

	// Validate required external tools
	if err := validateTools(); err != nil {
		logger.Error("tool validation failed", "error", err)
		os.Exit(1)
	}

	// Parse templates
	if err := loadTemplates(); err != nil {
		logger.Error("template loading failed", "error", err)
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/upload", handleUpload)
	http.HandleFunc("/health", handleHealth)

	logger.Info("server starting",
		"port", port,
		"dissect_path", dissectPath,
		"rules_path", rulesPath,
		"radare_backend", radareCmd,
		"radare_path", radareCmdPath,
		"gcs_bucket", gcsBucket,
	)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

// loadConfig loads configuration from environment variables.
func loadConfig() error {
	gcsBucket = os.Getenv("GCS_BUCKET")
	dissectPath = os.Getenv("DISSECT_PATH")
	rulesPath = os.Getenv("DISSECT_RULES_PATH")
	radare2Path = os.Getenv("RADARE2_PATH")
	rizinPath = os.Getenv("RIZIN_PATH")

	if dissectPath == "" {
		dissectPath = "dissect"
	}
	if radare2Path == "" {
		radare2Path = "radare2"
	}
	if rizinPath == "" {
		rizinPath = "rizin"
	}

	logger.Debug("configuration loaded",
		"DISSECT_PATH", dissectPath,
		"DISSECT_RULES_PATH", rulesPath,
		"RADARE2_PATH", radare2Path,
		"RIZIN_PATH", rizinPath,
		"GCS_BUCKET", gcsBucket,
		"PORT", os.Getenv("PORT"),
	)

	return nil
}

// validateTools checks that all required external tools are available.
func validateTools() error {
	var errs []error

	// Validate dissect binary
	dissectInfo, err := validateTool("dissect", dissectPath, "--version")
	if err != nil {
		errs = append(errs, fmt.Errorf("dissect: %w", err))
	} else {
		logger.Info("dissect binary validated",
			"path", dissectInfo.path,
			"version", dissectInfo.version,
		)
	}

	// Validate radare2 or rizin (dissect requires one of these)
	radareInfo, err := validateRadare()
	if err != nil {
		errs = append(errs, fmt.Errorf("radare2/rizin: %w", err))
	} else {
		radareCmd = radareInfo.name
		radareCmdPath = radareInfo.path
		logger.Info("radare backend validated",
			"backend", radareInfo.name,
			"path", radareInfo.path,
			"version", radareInfo.version,
		)
	}

	// Validate rules path if specified
	if rulesPath != "" {
		if info, err := os.Stat(rulesPath); err != nil {
			errs = append(errs, fmt.Errorf("rules path %q: %w", rulesPath, err))
		} else if !info.IsDir() {
			errs = append(errs, fmt.Errorf("rules path %q is not a directory", rulesPath))
		} else {
			// Count trait files
			traitCount, traitErr := countTraitFiles(rulesPath)
			if traitErr != nil {
				errs = append(errs, fmt.Errorf("rules path %q: failed to scan: %w", rulesPath, traitErr))
			} else if traitCount == 0 {
				errs = append(errs, fmt.Errorf("rules path %q contains no .yaml trait files", rulesPath))
			} else {
				logger.Info("rules path validated",
					"path", rulesPath,
					"trait_files", traitCount,
				)
			}
		}
	} else {
		logger.Debug("no custom rules path specified, using dissect defaults")
	}

	// Validate GCS bucket if configured
	if gcsBucket != "" {
		if err := validateGCSBucket(gcsBucket); err != nil {
			errs = append(errs, fmt.Errorf("GCS bucket %q: %w", gcsBucket, err))
		} else {
			logger.Info("GCS bucket validated",
				"bucket", gcsBucket,
			)
		}
	} else {
		logger.Debug("no GCS bucket configured, file archiving disabled")
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// validateTool checks if a tool exists and is executable.
func validateTool(name, path, versionFlag string) (*toolInfo, error) {
	// Resolve the full path
	resolvedPath, err := exec.LookPath(path)
	if err != nil {
		return nil, fmt.Errorf("not found in PATH: %w", err)
	}

	logger.Debug("tool path resolved",
		"name", name,
		"configured_path", path,
		"resolved_path", resolvedPath,
	)

	// Check it's executable
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat %q: %w", resolvedPath, err)
	}

	if info.Mode()&0111 == 0 {
		return nil, fmt.Errorf("%q is not executable", resolvedPath)
	}

	// Get version info
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolvedPath, versionFlag)
	output, err := cmd.CombinedOutput()
	version := strings.TrimSpace(string(output))
	if err != nil {
		logger.Warn("failed to get tool version",
			"name", name,
			"path", resolvedPath,
			"error", err,
			"output", version,
		)
		version = "unknown"
	}

	return &toolInfo{
		name:    name,
		path:    resolvedPath,
		version: version,
	}, nil
}

// countTraitFiles counts .yaml files recursively in a directory.
func countTraitFiles(dir string) (int, error) {
	count := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".yaml") {
			count++
		}
		return nil
	})
	return count, err
}

// validateGCSBucket checks that the GCS bucket exists and is accessible.
func validateGCSBucket(bucket string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger.Debug("validating GCS bucket connectivity",
		"bucket", bucket,
	)

	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create storage client: %w", err)
	}
	defer client.Close()

	// Check bucket exists and we have access
	_, err = client.Bucket(bucket).Attrs(ctx)
	if err != nil {
		return fmt.Errorf("failed to access bucket: %w", err)
	}

	return nil
}

// validateRadare checks for radare2 or rizin (fallback).
func validateRadare() (*toolInfo, error) {
	var radare2Err, rizinErr error

	// Try radare2 first
	if info, err := validateTool("radare2", radare2Path, "-v"); err == nil {
		return info, nil
	} else {
		radare2Err = err
		logger.Debug("radare2 not available",
			"configured_path", radare2Path,
			"error", err,
		)
	}

	// Fall back to rizin
	if info, err := validateTool("rizin", rizinPath, "-v"); err == nil {
		return info, nil
	} else {
		rizinErr = err
		logger.Debug("rizin not available",
			"configured_path", rizinPath,
			"error", err,
		)
	}

	return nil, fmt.Errorf("neither radare2 nor rizin found (radare2: %v; rizin: %v)", radare2Err, rizinErr)
}

// loadTemplates parses the HTML templates.
func loadTemplates() error {
	templateDir := "templates"

	// Check if templates directory exists
	if info, err := os.Stat(templateDir); err != nil {
		return fmt.Errorf("templates directory: %w", err)
	} else if !info.IsDir() {
		return fmt.Errorf("templates path is not a directory: %s", templateDir)
	}

	var err error
	uploadTemplate, err = template.ParseFiles(filepath.Join(templateDir, "upload.html"))
	if err != nil {
		return fmt.Errorf("parse upload.html: %w", err)
	}

	resultTemplate, err = template.ParseFiles(filepath.Join(templateDir, "result.html"))
	if err != nil {
		return fmt.Errorf("parse result.html: %w", err)
	}

	logger.Debug("templates loaded",
		"upload_template", "templates/upload.html",
		"result_template", "templates/result.html",
	)

	return nil
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := uploadTemplate.Execute(w, nil); err != nil {
		logger.Error("template execution failed",
			"template", "upload",
			"error", err,
		)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK\n"))
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()
	requestID := fmt.Sprintf("%d", time.Now().UnixNano())

	reqLogger := logger.With(
		"request_id", requestID,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
	)

	reqLogger.Info("upload request received")

	if r.Method != http.MethodPost {
		reqLogger.Warn("invalid method", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	if err := r.ParseMultipartForm(100 * 1024 * 1024); err != nil {
		reqLogger.Error("failed to parse multipart form", "error", err)
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		reqLogger.Error("failed to read uploaded file", "error", err)
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(fileHeader.Filename)
	reqLogger = reqLogger.With("filename", filename, "size", fileHeader.Size)
	reqLogger.Info("file received")

	tempFile, err := os.CreateTemp("", "dissect-*")
	if err != nil {
		reqLogger.Error("failed to create temp file", "error", err)
		http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
		return
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	reqLogger.Debug("temp file created", "path", tempPath)

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(tempFile, hash), file)
	if err != nil {
		tempFile.Close()
		reqLogger.Error("failed to write temp file", "error", err, "bytes_written", written)
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		return
	}
	tempFile.Close()

	sha256Hex := fmt.Sprintf("%x", hash.Sum(nil))
	reqLogger = reqLogger.With("sha256", sha256Hex)
	reqLogger.Info("file written to temp", "bytes", written)

	// Run dissect analysis
	analysisStart := time.Now()
	output, err := runDissect(ctx, tempPath, reqLogger)
	analysisDuration := time.Since(analysisStart)

	if err != nil {
		reqLogger.Error("dissect analysis failed",
			"error", err,
			"duration_ms", analysisDuration.Milliseconds(),
			"output_length", len(output),
		)
		output = fmt.Sprintf("Analysis failed: %v\n", err)
	} else {
		reqLogger.Info("dissect analysis completed",
			"duration_ms", analysisDuration.Milliseconds(),
			"output_length", len(output),
		)
	}

	htmlOutput := terminal.Render([]byte(output))

	// Upload to GCS if configured
	if gcsBucket != "" {
		gcsStart := time.Now()
		data, err := os.ReadFile(tempPath)
		if err != nil {
			reqLogger.Error("failed to read temp file for GCS upload", "error", err)
		} else {
			if err := uploadToGCS(ctx, gcsBucket, sha256Hex, filename, data, reqLogger); err != nil {
				reqLogger.Error("GCS upload failed",
					"error", err,
					"duration_ms", time.Since(gcsStart).Milliseconds(),
				)
			} else {
				reqLogger.Info("GCS upload completed",
					"bucket", gcsBucket,
					"object", fmt.Sprintf("%s/%s", sha256Hex, filename),
					"duration_ms", time.Since(gcsStart).Milliseconds(),
				)
			}
		}
	}

	data := resultData{
		Filename: html.EscapeString(filename),
		SHA256:   sha256Hex,
		Output:   template.HTML(htmlOutput),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := resultTemplate.Execute(w, data); err != nil {
		reqLogger.Error("template execution failed",
			"template", "result",
			"error", err,
		)
	}

	reqLogger.Info("request completed",
		"total_duration_ms", time.Since(requestStart).Milliseconds(),
	)
}

func runDissect(ctx context.Context, filePath string, reqLogger *slog.Logger) (string, error) {
	args := []string{"analyze", filePath, "--format", "terminal"}

	// Add rules path if configured
	if rulesPath != "" {
		args = append(args, "--rules", rulesPath)
	}

	// Log the file being analyzed
	fileInfo, statErr := os.Stat(filePath)
	if statErr != nil {
		reqLogger.Error("cannot stat input file",
			"file", filePath,
			"error", statErr,
		)
	} else {
		reqLogger.Debug("input file info",
			"file", filePath,
			"size", fileInfo.Size(),
			"mode", fileInfo.Mode().String(),
		)
	}

	// Resolve dissect path
	resolvedDissectPath, lookupErr := exec.LookPath(dissectPath)
	if lookupErr != nil {
		reqLogger.Error("dissect binary not found",
			"configured_path", dissectPath,
			"error", lookupErr,
			"PATH", os.Getenv("PATH"),
		)
		return "", fmt.Errorf("dissect binary not found: %w", lookupErr)
	}

	reqLogger.Debug("executing dissect",
		"configured_path", dissectPath,
		"resolved_path", resolvedDissectPath,
		"args", args,
		"file", filePath,
		"rules_path", rulesPath,
		"radare_backend", radareCmd,
		"radare_path", radareCmdPath,
	)

	// Log full environment for debugging
	reqLogger.Debug("dissect execution environment",
		"PATH", os.Getenv("PATH"),
		"HOME", os.Getenv("HOME"),
		"TMPDIR", os.Getenv("TMPDIR"),
		"working_dir", func() string { wd, _ := os.Getwd(); return wd }(),
	)

	cmd := exec.CommandContext(ctx, resolvedDissectPath, args...)
	startTime := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)

	if err != nil {
		// Copious error logging
		reqLogger.Error("dissect execution failed",
			"error", err,
			"duration_ms", duration.Milliseconds(),
			"configured_path", dissectPath,
			"resolved_path", resolvedDissectPath,
			"args", args,
			"input_file", filePath,
			"rules_path", rulesPath,
			"radare_backend", radareCmd,
			"radare_path", radareCmdPath,
			"output_length", len(output),
			"output_preview", truncateString(string(output), 2000),
		)

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			reqLogger.Error("dissect exit details",
				"exit_code", exitErr.ExitCode(),
				"process_state", exitErr.ProcessState.String(),
				"stderr_length", len(exitErr.Stderr),
				"stderr", string(exitErr.Stderr),
				"system_time_ms", exitErr.ProcessState.SystemTime().Milliseconds(),
				"user_time_ms", exitErr.ProcessState.UserTime().Milliseconds(),
			)
		}

		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			reqLogger.Error("dissect timed out",
				"timeout", "120s",
				"duration_ms", duration.Milliseconds(),
			)
		} else if errors.Is(ctx.Err(), context.Canceled) {
			reqLogger.Error("dissect was canceled",
				"duration_ms", duration.Milliseconds(),
			)
		}

		// Log PATH components for debugging
		pathDirs := strings.Split(os.Getenv("PATH"), ":")
		reqLogger.Debug("PATH directories", "dirs", pathDirs)

		return string(output), err
	}

	reqLogger.Debug("dissect completed successfully",
		"duration_ms", duration.Milliseconds(),
		"output_length", len(output),
	)

	return string(output), nil
}

// truncateString truncates a string to maxLen characters, adding "..." if truncated.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func uploadToGCS(ctx context.Context, bucket, sha256Hex, filename string, data []byte, reqLogger *slog.Logger) error {
	reqLogger.Debug("creating GCS client")

	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("storage client: %w", err)
	}
	defer client.Close()

	objectPath := fmt.Sprintf("%s/%s", sha256Hex, filename)
	reqLogger.Debug("uploading to GCS",
		"bucket", bucket,
		"object", objectPath,
		"size", len(data),
	)

	wc := client.Bucket(bucket).Object(objectPath).NewWriter(ctx)
	wc.ContentType = "application/octet-stream"

	if _, err := wc.Write(data); err != nil {
		wc.Close()
		return fmt.Errorf("write: %w", err)
	}

	return wc.Close()
}
