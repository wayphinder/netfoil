package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"

	"github.com/tinfoil-factory/netfoil/dns"
	"golang.org/x/sys/unix"
)

const usage = `SYNOPSIS
    netfoil [OPTIONS]

OPTIONS
        --ip
            IP to listen on (default: 127.0.0.1).

        --port
            UDP port to listen on (default: 53).

        --config-directory
			Config directory (default: /etc/netfoil).

        --disable-speculation
			Disable speculative execution (default: false).

        --pin-ca
            Path to CA to use (default: empty)

        --help, -h
			Print the help message.

Example
    $ netfoil --ip 127.0.0.1 --port 53 --config-directory /etc/netfoil`

func main() {
	options, err := processInput()
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	caCertPool, err := loadCACertPool(options.PinCA)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	err = disableSpeculation(options.DisableSpeculation)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	config, err := dns.ReadConfigFile(options.ConfigDirectory)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	configureLogger(config)

	conn, err := systemdSocketListener()
	if err != nil {
		println(err.Error())
	}

	if conn == nil {
		conn, err = bindService(options.IP, options.Port)
		if err != nil {
			println(err.Error())
			os.Exit(1)
		}
	}
	defer conn.Close()

	policy, err := dns.NewPolicy(options.ConfigDirectory, config.DenyPunycode, config.PinResponseDomain)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	err = dns.Server(conn, config, policy, caCertPool)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}
}

func loadCACertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}

	caCert, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("error parsing CA certificate")
	}

	return caCertPool, nil
}

func disableSpeculation(disable bool) error {
	if disable {
		_, _, err := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_SET_SPECULATION_CTRL, uintptr(unix.PR_SPEC_STORE_BYPASS), uintptr(unix.PR_SPEC_FORCE_DISABLE), 0, 0, 0)
		if err != 0 {
			return fmt.Errorf("error disabling store bypass speculation: %s\n", err)
		}

		_, _, err = syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_SET_SPECULATION_CTRL, uintptr(unix.PR_SPEC_INDIRECT_BRANCH), uintptr(unix.PR_SPEC_FORCE_DISABLE), 0, 0, 0)
		if err != 0 {
			return fmt.Errorf("error disabling store bypass speculation: %s\n", err)
		}

		/*
			err = unix.Prctl(unix.PR_SET_SPECULATION_CTRL, uintptr(unix.PR_SPEC_L1D_FLUSH), uintptr(unix.PR_SPEC_DISABLE), 0, 0)
			if err != nil {
				return fmt.Errorf("error setting L1D flush: %w\n", err)
			}
		*/
	}

	return nil
}

func configureLogger(config *dns.Config) {
	opts := &slog.HandlerOptions{
		Level: config.LogLevel,
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
	slog.SetDefault(logger)
}

func systemdSocketListener() (*net.UDPConn, error) {
	if _, ok := os.LookupEnv("LISTEN_FDS"); ok {
		f := os.NewFile(uintptr(3), "netfoil.socket")

		conn, err := net.FileConn(f)
		if err != nil {
			return nil, err
		}

		return conn.(*net.UDPConn), nil
	}

	return nil, fmt.Errorf("systemd socket listener not configured")
}

type Options struct {
	IP                 net.IP
	Port               int
	ConfigDirectory    string
	DisableSpeculation bool
	PinCA              string
}

func processInput() (*Options, error) {
	flags := flag.NewFlagSet("all", flag.ExitOnError)
	var help, h, disableSpeculation bool
	var configPath, ipString, pinCA string
	var portInt int
	flags.BoolVar(&help, "help", false, "")
	flags.BoolVar(&h, "h", false, "")
	flags.BoolVar(&disableSpeculation, "disable-speculation", false, "")
	flags.IntVar(&portInt, "port", 53, "")
	flags.StringVar(&ipString, "ip", "127.0.0.1", "")
	flags.StringVar(&configPath, "config-directory", "/etc/netfoil", "")
	flags.StringVar(&pinCA, "pin-ca", "", "")

	err := flags.Parse(os.Args[1:])
	if err != nil || help || h {
		fmt.Println(usage)
		os.Exit(1)
	}

	if portInt < 0 || portInt > 65535 {
		return nil, fmt.Errorf("invalid port %d", portInt)
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipString)
	}

	// TODO input validate configPath

	return &Options{
		IP:                 ip,
		Port:               portInt,
		ConfigDirectory:    configPath,
		DisableSpeculation: disableSpeculation,
		PinCA:              pinCA,
	}, nil
}

func bindService(ip net.IP, port int) (*net.UDPConn, error) {
	addr := net.UDPAddr{
		Port: port,
		IP:   ip,
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
