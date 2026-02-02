package config

import (
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// Watcher monitors a configuration file for changes.
type Watcher struct {
	path       string
	lastHash   [16]byte
	interval   time.Duration
	logger     *log.Logger
	onChange   func(*Config) error
	mu         sync.Mutex
	running    bool
	stopChan   chan struct{}
}

// NewWatcher creates a new configuration file watcher.
func NewWatcher(path string, interval time.Duration, logger *log.Logger, onChange func(*Config) error) *Watcher {
	return &Watcher{
		path:     path,
		interval: interval,
		logger:   logger,
		onChange: onChange,
		stopChan: make(chan struct{}),
	}
}

// Start begins watching the configuration file.
func (w *Watcher) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.running {
		return fmt.Errorf("watcher already running")
	}

	// Get initial hash
	hash, err := w.fileHash()
	if err != nil {
		return fmt.Errorf("failed to get initial file hash: %w", err)
	}
	w.lastHash = hash
	w.running = true

	go w.watchLoop()
	return nil
}

// Stop stops watching the configuration file.
func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return
	}

	w.running = false
	close(w.stopChan)
}

func (w *Watcher) watchLoop() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopChan:
			return
		case <-ticker.C:
			w.checkForChanges()
		}
	}
}

func (w *Watcher) checkForChanges() {
	hash, err := w.fileHash()
	if err != nil {
		// File might be temporarily unavailable during write
		// Log as debug/warn but don't stop
		return
	}

	w.mu.Lock()
	if hash == w.lastHash {
		w.mu.Unlock()
		return
	}
	w.lastHash = hash
	w.mu.Unlock()

	// File changed, reload configuration
	cfg, err := Load(w.path)
	if err != nil {
		w.logger.Printf("[WARN] [CONFIG] Failed to reload config: %v", err)
		return
	}

	if err := cfg.Validate(); err != nil {
		w.logger.Printf("[WARN] [CONFIG] Invalid configuration detected: %v", err)
		return
	}

	// Apply new configuration
	if w.onChange != nil {
		w.onChange(cfg)
	}
}

func (w *Watcher) fileHash() ([16]byte, error) {
	f, err := os.Open(w.path)
	if err != nil {
		return [16]byte{}, err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return [16]byte{}, err
	}

	var hash [16]byte
	copy(hash[:], h.Sum(nil))
	return hash, nil
}

// ForceReload triggers an immediate reload of the configuration.
func (w *Watcher) ForceReload() error {
	cfg, err := Load(w.path)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	if w.onChange != nil {
		return w.onChange(cfg)
	}
	return nil
}
