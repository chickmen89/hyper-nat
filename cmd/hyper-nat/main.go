// Hyper-NAT: Selective NAT software for Windows
// Uses WinDivert to intercept packets and apply NAT based on destination rules.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/igjeong/hyper-nat/config"
	"github.com/igjeong/hyper-nat/ipc"
	"github.com/igjeong/hyper-nat/nat"
	"github.com/igjeong/hyper-nat/service"
)

var (
	version   = "0.3.0"
	buildTime = "unknown"
)

func main() {
	// Check if running as Windows service
	if service.IsWindowsService() {
		// Parse flags for service mode
		fs := flag.NewFlagSet("service", flag.ExitOnError)
		configPath := fs.String("config", "hyper-nat.yaml", "Path to configuration file")
		logFile := fs.String("logfile", "", "Path to log file")
		verbose := fs.Bool("verbose", false, "Enable verbose logging")

		// Skip "service" and "run" arguments
		if len(os.Args) > 2 {
			fs.Parse(os.Args[3:])
		}

		if err := service.RunService(*configPath, *logFile, *verbose); err != nil {
			os.Exit(1)
		}
		return
	}

	// Check for subcommands first
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "status":
			runStatusCommand()
			return
		case "help", "-h", "--help":
			printUsage()
			return
		case "install":
			runInstallCommand()
			return
		case "uninstall":
			runUninstallCommand()
			return
		case "start":
			runStartCommand()
			return
		case "stop":
			runStopCommand()
			return
		case "service":
			// Service subcommand (used internally by SCM)
			if len(os.Args) > 2 && os.Args[2] == "run" {
				runServiceMode()
				return
			}
			printUsage()
			return
		}
	}

	// Parse command line flags for run mode
	configPath := flag.String("config", "hyper-nat.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	logFile := flag.String("logfile", "", "Path to log file (default: stdout)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Hyper-NAT v%s (built: %s)\n", version, buildTime)
		os.Exit(0)
	}

	// Run in foreground mode
	runForeground(*configPath, *logFile, *verbose)
}

func runForeground(configPath, logFile string, verbose bool) {
	// Setup logger
	logger, logCloser := setupLogger(logFile, verbose)
	if logCloser != nil {
		defer logCloser.Close()
	}

	logger.Printf("[INFO] [MAIN] Hyper-NAT v%s starting...", version)

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Fatalf("[ERROR] [MAIN] Failed to load config: %v", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		logger.Fatalf("[ERROR] [MAIN] Invalid configuration: %v", err)
	}

	logger.Printf("[INFO] [MAIN] Configuration loaded from %s", configPath)
	logger.Printf("[INFO] [MAIN] NAT IP: %s", cfg.NATIP)
	logger.Printf("[INFO] [MAIN] Internal Network: %s", cfg.InternalNetwork)
	logger.Printf("[INFO] [MAIN] Rules:")
	for i, rule := range cfg.Rules {
		logger.Printf("[INFO] [MAIN]   %d. %s: %s -> %s", i+1, rule.Name, rule.Destination, rule.Action)
	}

	// Create NAT engine
	engine := nat.NewEngine(cfg,
		nat.WithLogger(logger),
		nat.WithTCPTimeout(5*time.Minute),
		nat.WithUDPTimeout(30*time.Second),
		nat.WithICMPTimeout(30*time.Second),
		nat.WithTCPEstablishedTimeout(2*time.Hour),
		nat.WithMaxRetries(5),
		nat.WithRetryDelay(100*time.Millisecond, 5*time.Second),
		nat.WithVerbose(verbose),
	)

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Track start time for uptime
	startTime := time.Now()

	// Start IPC server for status queries
	ipcServer := ipc.NewServer(func() *ipc.StatusResponse {
		processed, natted, bypassed, dropped := engine.Stats()
		active, total := engine.TableStats()
		errorsRecovered := engine.ErrorsRecovered()
		uptime := time.Since(startTime)

		resp := &ipc.StatusResponse{
			Running:          true,
			Uptime:           uptime,
			UptimeStr:        formatDuration(uptime),
			PacketsProcessed: processed,
			PacketsNATted:    natted,
			PacketsBypassed:  bypassed,
			PacketsDropped:   dropped,
			ErrorsRecovered:  errorsRecovered,
			ActiveConns:      active,
			TotalConns:       total,
			NATIP:            cfg.NATIP.String(),
			InternalNetwork:  cfg.InternalNetwork.String(),
		}

		// Add connection details (convert from nat.ConnectionInfo to ipc.ConnectionInfo)
		natConns := engine.GetConnections()
		resp.Connections = make([]ipc.ConnectionInfo, len(natConns))
		for i, c := range natConns {
			resp.Connections[i] = ipc.ConnectionInfo{
				Protocol:     c.Protocol,
				InternalIP:   c.InternalIP,
				InternalPort: c.InternalPort,
				ExternalIP:   c.ExternalIP,
				ExternalPort: c.ExternalPort,
				NATPort:      c.NATPort,
				State:        c.State,
				IdleSeconds:  c.IdleSeconds,
			}
		}
		return resp
	})

	if err := ipcServer.Start(); err != nil {
		logger.Printf("[WARN] [MAIN] Failed to start IPC server: %v", err)
	} else {
		logger.Printf("[INFO] [MAIN] IPC server listening on %s", ipc.DefaultAddr)
	}
	defer ipcServer.Stop()

	// Start configuration file watcher for hot reload
	configWatcher := config.NewWatcher(configPath, 5*time.Second, logger, func(newCfg *config.Config) error {
		logger.Printf("[INFO] [MAIN] Configuration file changed, attempting hot reload...")
		if err := engine.UpdateRules(newCfg); err != nil {
			logger.Printf("[WARN] [MAIN] Hot reload failed: %v", err)
			return err
		}
		return nil
	})
	if err := configWatcher.Start(); err != nil {
		logger.Printf("[WARN] [MAIN] Failed to start config watcher: %v", err)
	} else {
		logger.Printf("[INFO] [MAIN] Configuration hot-reload enabled (watching %s)", configPath)
	}
	defer configWatcher.Stop()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start engine in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- engine.Start(ctx)
	}()

	// Wait for signal or error
	select {
	case sig := <-sigChan:
		logger.Printf("[INFO] [MAIN] Received signal %v, shutting down...", sig)
		// Stop engine first to close WinDivert handles (unblocks Recv calls)
		engine.Stop()
		cancel()
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			logger.Printf("[ERROR] [MAIN] Engine error: %v", err)
		}
		engine.Stop()
	}

	// Wait for engine goroutine to finish
	select {
	case <-errChan:
	case <-time.After(2 * time.Second):
		logger.Printf("[WARN] [MAIN] Engine did not stop gracefully")
	}

	// Print final statistics
	processed, natted, bypassed, dropped := engine.Stats()
	active, total := engine.TableStats()
	errorsRecovered := engine.ErrorsRecovered()
	logger.Printf("[INFO] [MAIN] Final statistics:")
	logger.Printf("[INFO] [MAIN]   Packets processed: %d", processed)
	logger.Printf("[INFO] [MAIN]   Packets NATted: %d", natted)
	logger.Printf("[INFO] [MAIN]   Packets bypassed: %d", bypassed)
	logger.Printf("[INFO] [MAIN]   Packets dropped: %d", dropped)
	logger.Printf("[INFO] [MAIN]   Errors recovered: %d", errorsRecovered)
	logger.Printf("[INFO] [MAIN]   Active connections: %d", active)
	logger.Printf("[INFO] [MAIN]   Total connections: %d", total)

	logger.Printf("[INFO] [MAIN] Hyper-NAT stopped")
}

func setupLogger(logFile string, verbose bool) (*log.Logger, io.Closer) {
	var writer io.Writer = os.Stdout
	var closer io.Closer

	if logFile != "" {
		// Ensure log directory exists
		logDir := filepath.Dir(logFile)
		if logDir != "" && logDir != "." {
			if err := os.MkdirAll(logDir, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to create log directory: %v\n", err)
			}
		}

		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to open log file: %v, using stdout\n", err)
		} else {
			// Write to both file and stdout
			writer = io.MultiWriter(os.Stdout, f)
			closer = f
		}
	}

	flags := log.LstdFlags
	if verbose {
		flags |= log.Lmicroseconds
	}

	return log.New(writer, "", flags), closer
}

func runServiceMode() {
	fs := flag.NewFlagSet("service", flag.ExitOnError)
	configPath := fs.String("config", "hyper-nat.yaml", "Path to configuration file")
	logFile := fs.String("logfile", "", "Path to log file")
	verbose := fs.Bool("verbose", false, "Enable verbose logging")

	// Skip "service" and "run" arguments
	if len(os.Args) > 2 {
		fs.Parse(os.Args[3:])
	}

	if err := service.RunService(*configPath, *logFile, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Service error: %v\n", err)
		os.Exit(1)
	}
}

func runInstallCommand() {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to configuration file")
	logFile := fs.String("logfile", "", "Path to log file")
	fs.Parse(os.Args[2:])

	// Use absolute paths
	if *configPath != "" {
		absPath, err := filepath.Abs(*configPath)
		if err == nil {
			*configPath = absPath
		}
	}
	if *logFile != "" {
		absPath, err := filepath.Abs(*logFile)
		if err == nil {
			*logFile = absPath
		}
	}

	fmt.Printf("Installing Hyper-NAT service...\n")
	if err := service.Install(*configPath, *logFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Service installed successfully.\n")
	fmt.Printf("\nTo start the service:\n")
	fmt.Printf("  hyper-nat start\n")
	fmt.Printf("  or: net start HyperNAT\n")
}

func runUninstallCommand() {
	fmt.Printf("Uninstalling Hyper-NAT service...\n")
	if err := service.Uninstall(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Service uninstalled successfully.\n")
}

func runStartCommand() {
	fmt.Printf("Starting Hyper-NAT service...\n")
	if err := service.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Service started.\n")
}

func runStopCommand() {
	fmt.Printf("Stopping Hyper-NAT service...\n")
	if err := service.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Service stopped.\n")
}

func printUsage() {
	fmt.Printf(`Hyper-NAT v%s - Selective NAT software for Windows

Usage:
  hyper-nat [flags]              Run the NAT engine (foreground)
  hyper-nat status               Show status of running instance
  hyper-nat install [flags]      Install as Windows service
  hyper-nat uninstall            Uninstall Windows service
  hyper-nat start                Start the Windows service
  hyper-nat stop                 Stop the Windows service
  hyper-nat help                 Show this help message

Run Flags:
  -config string   Path to configuration file (default "hyper-nat.yaml")
  -logfile string  Path to log file (default: stdout only)
  -verbose         Enable verbose logging
  -version         Show version information

Install Flags:
  -config string   Path to configuration file (will be used by service)
  -logfile string  Path to log file (will be used by service)

Examples:
  # Run in foreground
  hyper-nat -config configs\hyper-nat.yaml -verbose

  # Run with log file
  hyper-nat -config configs\hyper-nat.yaml -logfile logs\hyper-nat.log

  # Install as service
  hyper-nat install -config C:\hyper-nat\configs\hyper-nat.yaml -logfile C:\hyper-nat\logs\hyper-nat.log

  # Manage service
  hyper-nat start
  hyper-nat status
  hyper-nat stop
  hyper-nat uninstall
`, version)
}

func runStatusCommand() {
	client := ipc.NewClient()

	status, err := client.GetStatus()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("\nHyper-NAT is not running. Start it with:")
		fmt.Println("  hyper-nat -config configs\\hyper-nat.yaml")
		fmt.Println("  or: hyper-nat start (if installed as service)")
		os.Exit(1)
	}

	fmt.Printf("Hyper-NAT Status\n")
	fmt.Printf("================\n\n")
	fmt.Printf("Status:           Running\n")
	fmt.Printf("Uptime:           %s\n", status.UptimeStr)
	fmt.Printf("NAT IP:           %s\n", status.NATIP)
	fmt.Printf("Internal Network: %s\n\n", status.InternalNetwork)

	fmt.Printf("Packet Statistics\n")
	fmt.Printf("-----------------\n")
	fmt.Printf("Processed:        %d\n", status.PacketsProcessed)
	fmt.Printf("NATted:           %d\n", status.PacketsNATted)
	fmt.Printf("Bypassed:         %d\n", status.PacketsBypassed)
	fmt.Printf("Dropped:          %d\n", status.PacketsDropped)
	fmt.Printf("Errors Recovered: %d\n\n", status.ErrorsRecovered)

	fmt.Printf("Connection Table\n")
	fmt.Printf("----------------\n")
	fmt.Printf("Active:           %d\n", status.ActiveConns)
	fmt.Printf("Total:            %d\n\n", status.TotalConns)

	if len(status.Connections) > 0 {
		fmt.Printf("Active Connections (showing up to 20)\n")
		fmt.Printf("-------------------------------------\n")
		fmt.Printf("%-6s %-21s %-21s %-8s %-12s %s\n",
			"Proto", "Internal", "External", "NAT Port", "State", "Idle")

		shown := 0
		for _, conn := range status.Connections {
			if shown >= 20 {
				fmt.Printf("... and %d more\n", len(status.Connections)-20)
				break
			}

			internal := fmt.Sprintf("%s:%d", conn.InternalIP, conn.InternalPort)
			external := fmt.Sprintf("%s:%d", conn.ExternalIP, conn.ExternalPort)
			idle := formatSeconds(conn.IdleSeconds)

			fmt.Printf("%-6s %-21s %-21s %-8d %-12s %s\n",
				conn.Protocol, internal, external, conn.NATPort, conn.State, idle)
			shown++
		}
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func formatSeconds(s int64) string {
	if s < 60 {
		return fmt.Sprintf("%ds", s)
	}
	if s < 3600 {
		return fmt.Sprintf("%dm %ds", s/60, s%60)
	}
	return fmt.Sprintf("%dh %dm", s/3600, (s%3600)/60)
}

// protoName converts protocol number to string (duplicated to avoid import cycle)
func protoNameStr(proto string) string {
	return strings.ToUpper(proto)
}
