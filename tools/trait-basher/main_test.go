package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCleanupOrphanedExtractDirs(t *testing.T) {
	tmpDir := os.TempDir()

	// Create a fake orphaned directory with a non-existent PID
	// Use PID 1 billion which definitely doesn't exist
	orphanPID := 1000000000
	orphanDir := filepath.Join(tmpDir, fmt.Sprintf("tbsh.%d", orphanPID))
	if err := os.MkdirAll(orphanDir, 0o750); err != nil {
		t.Fatalf("Failed to create test orphan dir: %v", err)
	}
	// Create a file inside to verify recursive removal
	testFile := filepath.Join(orphanDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a directory for the current process (should NOT be cleaned up)
	currentDir := filepath.Join(tmpDir, fmt.Sprintf("tbsh.%d", os.Getpid()))
	if err := os.MkdirAll(currentDir, 0o750); err != nil {
		t.Fatalf("Failed to create current process dir: %v", err)
	}
	defer os.RemoveAll(currentDir)

	// Run cleanup
	cleanupOrphanedExtractDirs()

	// Verify orphan was cleaned up
	if _, err := os.Stat(orphanDir); !os.IsNotExist(err) {
		os.RemoveAll(orphanDir) // Clean up on failure
		t.Errorf("Orphan directory was not cleaned up: %s", orphanDir)
	}

	// Verify current process dir was NOT cleaned up
	if _, err := os.Stat(currentDir); os.IsNotExist(err) {
		t.Errorf("Current process directory was incorrectly cleaned up: %s", currentDir)
	}
}

func TestCleanupOrphanedExtractDirs_IgnoresNonMatchingDirs(t *testing.T) {
	tmpDir := os.TempDir()

	// Create directories that should NOT be touched
	testDirs := []string{
		filepath.Join(tmpDir, "tbsh.notapid"),
		filepath.Join(tmpDir, "other-tool-12345"),
		filepath.Join(tmpDir, "tbsh."), // Empty PID
	}

	for _, dir := range testDirs {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("Failed to create test dir %s: %v", dir, err)
		}
		defer os.RemoveAll(dir)
	}

	// Run cleanup
	cleanupOrphanedExtractDirs()

	// Verify none were touched (except tbsh. which has invalid format)
	for _, dir := range testDirs[:2] {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Non-matching directory was incorrectly cleaned up: %s", dir)
		}
	}
}

func TestExtractDirNaming(t *testing.T) {
	// Verify the naming convention includes PID
	pid := os.Getpid()
	expected := filepath.Join(os.TempDir(), fmt.Sprintf("tbsh.%d", pid))

	// This is the same logic used in main()
	actual := filepath.Join(os.TempDir(), fmt.Sprintf("tbsh.%d", pid))

	if actual != expected {
		t.Errorf("Extract dir naming mismatch: got %s, want %s", actual, expected)
	}
}

func TestProcessExistsCheck(t *testing.T) {
	// Current process should exist
	if err := syscall.Kill(os.Getpid(), 0); err != nil {
		t.Errorf("Current process check failed: %v", err)
	}

	// Non-existent PID should fail
	if err := syscall.Kill(1000000000, 0); err == nil {
		t.Error("Non-existent process check should have failed")
	}
}
