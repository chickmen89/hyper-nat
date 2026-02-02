// Package service provides Windows service functionality for Hyper-NAT.
package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/igjeong/hyper-nat/config"
	"github.com/igjeong/hyper-nat/ipc"
	"github.com/igjeong/hyper-nat/nat"
)

const (
	ServiceName        = "HyperNAT"
	ServiceDisplayName = "Hyper-NAT Service"
	ServiceDescription = "Selective NAT software for Windows using WinDivert"
)

// HyperNATService implements the Windows service interface.
type HyperNATService struct {
	configPath string
	logFile    string
	verbose    bool
	logger     *log.Logger
	engine     *nat.Engine
	ipcServer  *ipc.Server
}

// NewService creates a new Hyper-NAT service instance.
func NewService(configPath, logFile string, verbose bool) *HyperNATService {
	return &HyperNATService{
		configPath: configPath,
		logFile:    logFile,
		verbose:    verbose,
	}
}

// Execute is the main service loop called by Windows SCM.
func (s *HyperNATService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	// Setup logging
	if err := s.setupLogging(); err != nil {
		elog, _ := eventlog.Open(ServiceName)
		if elog != nil {
			elog.Error(1, fmt.Sprintf("Failed to setup logging: %v", err))
			elog.Close()
		}
		return false, 1
	}

	// Load configuration
	cfg, err := config.Load(s.configPath)
	if err != nil {
		s.logger.Printf("[ERROR] [SERVICE] Failed to load config: %v", err)
		return false, 1
	}

	if err := cfg.Validate(); err != nil {
		s.logger.Printf("[ERROR] [SERVICE] Invalid configuration: %v", err)
		return false, 1
	}

	s.logger.Printf("[INFO] [SERVICE] Configuration loaded from %s", s.configPath)
	s.logger.Printf("[INFO] [SERVICE] NAT IP: %s", cfg.NATIP)
	s.logger.Printf("[INFO] [SERVICE] Internal Network: %s", cfg.InternalNetwork)

	// Create NAT engine
	s.engine = nat.NewEngine(cfg,
		nat.WithLogger(s.logger),
		nat.WithTCPTimeout(5*time.Minute),
		nat.WithUDPTimeout(30*time.Second),
		nat.WithICMPTimeout(30*time.Second),
		nat.WithTCPEstablishedTimeout(2*time.Hour),
		nat.WithMaxRetries(5),
		nat.WithRetryDelay(100*time.Millisecond, 5*time.Second),
		nat.WithVerbose(s.verbose),
	)

	// Setup context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startTime := time.Now()

	// Start IPC server
	s.ipcServer = ipc.NewServer(func() *ipc.StatusResponse {
		processed, natted, bypassed, dropped := s.engine.Stats()
		active, total := s.engine.TableStats()
		errorsRecovered := s.engine.ErrorsRecovered()
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
			ActiveDNATConns:  s.engine.DNATSessionCount(),
		}

		// Add SNAT connection details
		natConns := s.engine.GetConnections()
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

		// Add port forwarding rules
		pfRules := s.engine.GetPortForwardRules()
		resp.PortForwards = make([]ipc.PortForwardInfo, len(pfRules))
		for i, r := range pfRules {
			resp.PortForwards[i] = ipc.PortForwardInfo{
				Name:         r.Name,
				Protocol:     r.Protocol,
				ExternalPort: r.ExternalPort,
				InternalIP:   r.InternalIP,
				InternalPort: r.InternalPort,
			}
		}

		// Add DNAT sessions
		dnatSessions := s.engine.GetDNATSessions()
		resp.DNATSessions = make([]ipc.DNATSessionInfo, len(dnatSessions))
		for i, sess := range dnatSessions {
			resp.DNATSessions[i] = ipc.DNATSessionInfo{
				Protocol:     sess.Protocol,
				ExternalIP:   sess.ExternalIP,
				ExternalPort: sess.ExternalPort,
				InternalIP:   sess.InternalIP,
				InternalPort: sess.InternalPort,
				NATPort:      sess.NATPort,
				IdleSeconds:  sess.IdleSeconds,
			}
		}

		return resp
	})

	if err := s.ipcServer.Start(); err != nil {
		s.logger.Printf("[WARN] [SERVICE] Failed to start IPC server: %v", err)
	} else {
		s.logger.Printf("[INFO] [SERVICE] IPC server listening on %s", ipc.DefaultAddr)
	}

	// Start config watcher
	configWatcher := config.NewWatcher(s.configPath, 5*time.Second, s.logger, func(newCfg *config.Config) error {
		s.logger.Printf("[INFO] [SERVICE] Configuration file changed, attempting hot reload...")
		if err := s.engine.UpdateRules(newCfg); err != nil {
			s.logger.Printf("[WARN] [SERVICE] Hot reload failed: %v", err)
			return err
		}
		return nil
	})
	if err := configWatcher.Start(); err != nil {
		s.logger.Printf("[WARN] [SERVICE] Failed to start config watcher: %v", err)
	}

	// Start engine in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- s.engine.Start(ctx)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	s.logger.Printf("[INFO] [SERVICE] Hyper-NAT service started")

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s.logger.Printf("[INFO] [SERVICE] Received stop signal")
				break loop
			default:
				s.logger.Printf("[WARN] [SERVICE] Unexpected control request: %v", c)
			}
		case err := <-errChan:
			if err != nil && err != context.Canceled {
				s.logger.Printf("[ERROR] [SERVICE] Engine error: %v", err)
			}
			break loop
		}
	}

	changes <- svc.Status{State: svc.StopPending}

	// Cleanup
	configWatcher.Stop()
	s.engine.Stop()
	cancel()
	s.ipcServer.Stop()

	// Wait for engine to stop
	select {
	case <-errChan:
	case <-time.After(2 * time.Second):
	}

	// Log final statistics
	processed, natted, bypassed, dropped := s.engine.Stats()
	active, total := s.engine.TableStats()
	errorsRecovered := s.engine.ErrorsRecovered()
	s.logger.Printf("[INFO] [SERVICE] Final statistics:")
	s.logger.Printf("[INFO] [SERVICE]   Packets processed: %d", processed)
	s.logger.Printf("[INFO] [SERVICE]   Packets NATted: %d", natted)
	s.logger.Printf("[INFO] [SERVICE]   Packets bypassed: %d", bypassed)
	s.logger.Printf("[INFO] [SERVICE]   Packets dropped: %d", dropped)
	s.logger.Printf("[INFO] [SERVICE]   Errors recovered: %d", errorsRecovered)
	s.logger.Printf("[INFO] [SERVICE]   Active connections: %d", active)
	s.logger.Printf("[INFO] [SERVICE]   Total connections: %d", total)

	s.logger.Printf("[INFO] [SERVICE] Hyper-NAT service stopped")
	return false, 0
}

func (s *HyperNATService) setupLogging() error {
	if s.logFile != "" {
		// Ensure log directory exists
		logDir := filepath.Dir(s.logFile)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}

		f, err := os.OpenFile(s.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		s.logger = log.New(f, "", log.LstdFlags)
	} else {
		// When running as service without log file, use event log
		s.logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	if s.verbose {
		s.logger.SetFlags(log.LstdFlags | log.Lmicroseconds)
	}
	return nil
}

// Install installs the Windows service.
func Install(configPath, logFile string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", ServiceName)
	}

	// Build service arguments
	args := []string{"service", "run"}
	if configPath != "" {
		args = append(args, "-config", configPath)
	}
	if logFile != "" {
		args = append(args, "-logfile", logFile)
	}

	svcConfig := mgr.Config{
		DisplayName:  ServiceDisplayName,
		Description:  ServiceDescription,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}

	s, err = m.CreateService(ServiceName, exePath, svcConfig, args...)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer s.Close()

	// Setup event log
	err = eventlog.InstallAsEventCreate(ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		return fmt.Errorf("failed to setup event log: %w", err)
	}

	return nil
}

// Uninstall removes the Windows service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()

	// Stop service if running
	status, err := s.Query()
	if err == nil && status.State != svc.Stopped {
		s.Control(svc.Stop)
		// Wait for service to stop
		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			status, err = s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
		}
	}

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	eventlog.Remove(ServiceName)
	return nil
}

// Start starts the Windows service.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

// Stop stops the Windows service.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	// Wait for service to stop
	for i := 0; i < 20; i++ {
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("failed to query service status: %w", err)
		}
	}

	return fmt.Errorf("service did not stop in time")
}

// RunService runs the service (called from main when running as service).
func RunService(configPath, logFile string, verbose bool) error {
	svc := NewService(configPath, logFile, verbose)
	return svc.Run()
}

// Run starts the service execution.
func (s *HyperNATService) Run() error {
	return svc.Run(ServiceName, s)
}

// IsWindowsService checks if the program is running as a Windows service.
func IsWindowsService() bool {
	isService, _ := svc.IsWindowsService()
	return isService
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	sec := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, sec)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, sec)
	}
	return fmt.Sprintf("%ds", sec)
}
