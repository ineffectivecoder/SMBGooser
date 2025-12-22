package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/SMBGooser/pkg/srvsvc"
	"github.com/ineffectivecoder/SMBGooser/pkg/wkssvc"
)

func init() {
	commands.Register(&Command{
		Name:        "sessions",
		Aliases:     []string{"who"},
		Description: "Enumerate active sessions (who's connected)",
		Usage:       "sessions",
		Handler:     cmdSessions,
	})

	commands.Register(&Command{
		Name:        "loggedon",
		Aliases:     []string{"logged"},
		Description: "Enumerate logged-on users",
		Usage:       "loggedon",
		Handler:     cmdLoggedOn,
	})
}

// cmdSessions enumerates active sessions
func cmdSessions(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	info_("Connecting to Server Service...")
	srvClient, err := srvsvc.NewClient(client)
	if err != nil {
		return fmt.Errorf("failed to create SRVSVC client: %w", err)
	}
	defer srvClient.Close()

	info_("Enumerating sessions...")
	sessions, err := srvClient.EnumSessions("")
	if err != nil {
		return fmt.Errorf("failed to enumerate sessions: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %sActive Sessions on %s:%s\n", colorBold, targetHost, colorReset)
	fmt.Println("  " + strings.Repeat("-", 60))

	if len(sessions) == 0 {
		fmt.Println("  No active sessions found (or access denied)")
	} else {
		fmt.Printf("  %-20s %-20s %-10s %s\n", "CLIENT", "USER", "TIME", "IDLE")
		fmt.Println("  " + strings.Repeat("-", 60))
		for _, s := range sessions {
			fmt.Printf("  %-20s %-20s %-10d %d\n",
				s.ClientName, s.UserName, s.Time, s.IdleTime)
		}
	}

	fmt.Println()
	success_("Found %d session(s)", len(sessions))

	// Also try to enumerate shares via RPC
	info_("Enumerating shares via RPC...")
	shares, err := srvClient.EnumShares("")
	if err == nil && len(shares) > 0 {
		fmt.Println()
		fmt.Printf("  %sShares (via SRVSVC):%s\n", colorBold, colorReset)
		for _, s := range shares {
			fmt.Printf("  %s\n", s.Name)
		}
	}

	return nil
}

// cmdLoggedOn enumerates logged-on users
func cmdLoggedOn(ctx context.Context, args []string) error {
	if client == nil || session == nil {
		return fmt.Errorf("not connected")
	}

	info_("Connecting to Workstation Service...")
	wksClient, err := wkssvc.NewClient(client)
	if err != nil {
		return fmt.Errorf("failed to create WKSSVC client: %w", err)
	}
	defer wksClient.Close()

	info_("Enumerating logged-on users...")
	users, err := wksClient.EnumLoggedOnUsers("")
	if err != nil {
		return fmt.Errorf("failed to enumerate users: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %sLogged-On Users on %s:%s\n", colorBold, targetHost, colorReset)
	fmt.Println("  " + strings.Repeat("-", 60))

	if len(users) == 0 {
		fmt.Println("  No logged-on users found (or access denied)")
	} else {
		fmt.Printf("  %-20s %-20s %s\n", "USER", "DOMAIN", "LOGON SERVER")
		fmt.Println("  " + strings.Repeat("-", 60))
		for _, u := range users {
			fmt.Printf("  %-20s %-20s %s\n",
				u.UserName, u.LogonDomain, u.LogonServer)
		}
	}

	fmt.Println()
	success_("Found %d user(s)", len(users))

	// Also get workstation info
	info_("Getting workstation info...")
	wsInfo, err := wksClient.GetWorkstationInfo("")
	if err == nil && wsInfo != nil {
		fmt.Printf("  Computer: %s  Domain: %s\n", wsInfo.ComputerName, wsInfo.Domain)
	}

	return nil
}
