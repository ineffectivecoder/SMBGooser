package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/svcctl"
)

func init() {
	commands.Register(&Command{
		Name:        "svc",
		Aliases:     []string{"services"},
		Description: "Service enumeration and control",
		Usage:       "svc <list|query|start|stop> ...",
		Handler:     cmdSvc,
	})
}

// cmdSvc handles service operations
func cmdSvc(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	if len(args) < 1 {
		printSvcHelp()
		return nil
	}

	switch strings.ToLower(args[0]) {
	case "list":
		return cmdSvcList(ctx, args[1:])
	case "query":
		return cmdSvcQuery(ctx, args[1:])
	case "start":
		return cmdSvcStart(ctx, args[1:])
	case "stop":
		return cmdSvcStop(ctx, args[1:])
	default:
		printSvcHelp()
		return nil
	}
}

func printSvcHelp() {
	fmt.Println("\nService subcommands:")
	fmt.Println("  list                    List all services")
	fmt.Println("  query <service_name>    Query service status")
	fmt.Println("  start <service_name>    Start a service")
	fmt.Println("  stop <service_name>     Stop a service")
	fmt.Println("\nExamples:")
	fmt.Println("  svc list")
	fmt.Println("  svc query Spooler")
	fmt.Println("  svc start RemoteRegistry")
	fmt.Println()
}

// cmdSvcList lists all services
func cmdSvcList(ctx context.Context, args []string) error {
	// Enable debug output if verbose mode
	svcctl.Debug = verbose

	info_("Connecting to Service Control Manager...")
	svcClient, err := svcctl.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create SCMR client: %w", err)
	}
	defer svcClient.Close()

	// Open SCM with enumerate rights
	if err := svcClient.OpenSCManager("", svcctl.SCManagerEnumerateService|svcctl.SCManagerConnect); err != nil {
		return fmt.Errorf("failed to open SCM: %w", err)
	}

	info_("Enumerating services...")
	// SERVICE_WIN32 (0x30) = both OwnProcess and ShareProcess
	// SERVICE_STATE_ALL (3) = running + stopped
	services, err := svcClient.EnumServices(0x30, 3)
	if err != nil {
		return fmt.Errorf("failed to enumerate services: %w", err)
	}

	if len(services) == 0 {
		fmt.Println("\n  No services found (or enumeration not yet fully implemented)")
		fmt.Println("  Use 'svc query <name>' to query individual services")
		return nil
	}

	fmt.Println()
	fmt.Printf("  %s%-40s %-15s %s%s\n", colorBold, "Service Name", "State", "Type", colorReset)
	fmt.Println("  " + strings.Repeat("-", 70))

	for _, svc := range services {
		state := svc.Status.CurrentState.String()
		typeStr := svc.Status.ServiceType.String()
		fmt.Printf("  %-40s %-15s %s\n", svc.ServiceName, state, typeStr)
	}
	fmt.Println()

	return nil
}

// cmdSvcQuery queries a specific service
func cmdSvcQuery(ctx context.Context, args []string) error {
	if len(args) < 1 {
		fmt.Println("Usage: svc query <service_name>")
		return nil
	}

	serviceName := args[0]

	info_("Connecting to Service Control Manager...")
	svcClient, err := svcctl.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create SCMR client: %w", err)
	}
	defer svcClient.Close()

	if err := svcClient.OpenSCManager("", svcctl.SCManagerConnect); err != nil {
		return fmt.Errorf("failed to open SCM: %w", err)
	}

	info_("Opening service: %s", serviceName)
	handle, err := svcClient.OpenService(serviceName, svcctl.ServiceQueryStatus)
	if err != nil {
		return fmt.Errorf("failed to open service: %w", err)
	}
	defer svcClient.CloseHandle(handle)

	status, err := svcClient.QueryServiceStatus(handle)
	if err != nil {
		return fmt.Errorf("failed to query status: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %sService:%s %s\n", colorBold, colorReset, serviceName)
	fmt.Printf("  %sState:%s   %s\n", colorBold, colorReset, status.CurrentState.String())
	fmt.Printf("  %sType:%s    %s\n", colorBold, colorReset, status.ServiceType.String())
	fmt.Println()

	return nil
}

// cmdSvcStart starts a service
func cmdSvcStart(ctx context.Context, args []string) error {
	if len(args) < 1 {
		fmt.Println("Usage: svc start <service_name>")
		return nil
	}

	serviceName := args[0]

	info_("Connecting to Service Control Manager...")
	svcClient, err := svcctl.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create SCMR client: %w", err)
	}
	defer svcClient.Close()

	if err := svcClient.OpenSCManager("", svcctl.SCManagerConnect); err != nil {
		return fmt.Errorf("failed to open SCM: %w", err)
	}

	info_("Opening service: %s", serviceName)
	handle, err := svcClient.OpenService(serviceName, svcctl.ServiceStart|svcctl.ServiceQueryStatus)
	if err != nil {
		return fmt.Errorf("failed to open service: %w", err)
	}
	defer svcClient.CloseHandle(handle)

	info_("Starting service...")
	if err := svcClient.StartService(handle); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	success_("Service started: %s", serviceName)
	return nil
}

// cmdSvcStop stops a service
func cmdSvcStop(ctx context.Context, args []string) error {
	if len(args) < 1 {
		fmt.Println("Usage: svc stop <service_name>")
		return nil
	}

	serviceName := args[0]

	info_("Connecting to Service Control Manager...")
	svcClient, err := svcctl.NewClient(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create SCMR client: %w", err)
	}
	defer svcClient.Close()

	if err := svcClient.OpenSCManager("", svcctl.SCManagerConnect); err != nil {
		return fmt.Errorf("failed to open SCM: %w", err)
	}

	info_("Opening service: %s", serviceName)
	handle, err := svcClient.OpenService(serviceName, svcctl.ServiceStop|svcctl.ServiceQueryStatus)
	if err != nil {
		return fmt.Errorf("failed to open service: %w", err)
	}
	defer svcClient.CloseHandle(handle)

	info_("Stopping service...")
	status, err := svcClient.StopService(handle)
	if err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	if status != nil {
		success_("Service stopping: %s (state: %s)", serviceName, status.CurrentState.String())
	} else {
		success_("Stop command sent to: %s", serviceName)
	}
	return nil
}
