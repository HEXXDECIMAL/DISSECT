package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"cloud.google.com/go/storage"
	"github.com/buildkite/terminal-to-html"
)

var (
	uploadTemplate *template.Template
	resultTemplate *template.Template
	gcsBucket      string
	dissectPath    string
)

type resultData struct {
	Filename string
	SHA256   string
	GCSPath  string
	Output   template.HTML
}

func init() {
	var err error
	uploadTemplate, err = template.ParseFiles("templates/upload.html")
	if err != nil {
		log.Fatalf("Failed to parse upload template: %v", err)
	}

	resultTemplate, err = template.ParseFiles("templates/result.html")
	if err != nil {
		log.Fatalf("Failed to parse result template: %v", err)
	}

	gcsBucket = os.Getenv("GCS_BUCKET")
	dissectPath = os.Getenv("DISSECT_PATH")
	if dissectPath == "" {
		dissectPath = "dissect"
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/upload", handleUpload)
	http.HandleFunc("/health", handleHealth)

	log.Printf("Starting server on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := uploadTemplate.Execute(w, nil); err != nil {
		log.Printf("Template error: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK\n"))
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	if err := r.ParseMultipartForm(100 * 1024 * 1024); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(fileHeader.Filename)

	tempFile, err := os.CreateTemp("", "dissect-*")
	if err != nil {
		http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())

	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tempFile, hash), file); err != nil {
		tempFile.Close()
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		return
	}
	tempFile.Close()

	sha256Hex := fmt.Sprintf("%x", hash.Sum(nil))

	output, err := runDissect(ctx, tempFile.Name())
	if err != nil {
		log.Printf("Dissect error: %v", err)
		output = fmt.Sprintf("Analysis failed: %v\n", err)
	}

	htmlOutput := terminal.Render([]byte(output))

	if gcsBucket != "" {
		data, err := os.ReadFile(tempFile.Name())
		if err == nil {
			if err := uploadToGCS(ctx, gcsBucket, sha256Hex, filename, data); err != nil {
				log.Printf("GCS upload error: %v", err)
			}
		}
	}

	data := resultData{
		Filename: html.EscapeString(filename),
		SHA256:   sha256Hex,
		GCSPath:  fmt.Sprintf("gs://%s/%s/%s", gcsBucket, sha256Hex, html.EscapeString(filename)),
		Output:   template.HTML(htmlOutput),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := resultTemplate.Execute(w, data); err != nil {
		log.Printf("Template error: %v", err)
	}
}

func runDissect(ctx context.Context, filepath string) (string, error) {
	cmd := exec.CommandContext(ctx, dissectPath, "analyze", filepath, "--format", "terminal")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func uploadToGCS(ctx context.Context, bucket, sha256, filename string, data []byte) error {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("storage client: %w", err)
	}
	defer client.Close()

	objectPath := fmt.Sprintf("%s/%s", sha256, filename)
	wc := client.Bucket(bucket).Object(objectPath).NewWriter(ctx)
	wc.ContentType = "application/octet-stream"

	if _, err := wc.Write(data); err != nil {
		wc.Close()
		return fmt.Errorf("write: %w", err)
	}

	return wc.Close()
}
