// hostel - A simple reverse proxy for local development
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type Project struct {
	Name string
	Path string
	Port int
	Cmd  *exec.Cmd
}

func main() {
	println(`
 _               _       _
| |__   ___  ___| |_ ___| |
| '_ \ / _ \/ __| __/ _ \ |
| | | | (_) \__ \ ||  __/ |
|_| |_|\___/|___/\__\___|_|

A simple reverse proxy for local development
`)

	// Define CLI flags
	domainFlag := flag.String("domain", "localhost", "Custom domain to use for projects (default: localhost)")
	flag.Parse()

	// Get the directory to scan (default to current directory)
	args := flag.Args()
	scanDir := "."
	if len(args) > 0 {
		scanDir = args[0]
	}

	domain := *domainFlag

	projects, err := detectProjects(scanDir)
	if err != nil {
		fatal("Failed to detect projects: %v", err)
	}

	if len(projects) == 0 {
		fatal("No projects found in %s", scanDir)
	}

	certPath, keyPath := domain+".crt", domain+".key"
	if !fileExists(certPath) || !fileExists(keyPath) {
		println("Generating TLS certificate...")
		err = generateCertificate(certPath, keyPath, domain)
		if err != nil {
			fatal("Failed to generate TLS certificate: %v", err)
		}
		println("TLS certificate generated successfully")
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	var dnsServer *dns.Server
	if domain == "localhost" {
		dnsServer = StartDNSServer()
	}

	startProjects(projects)

	server := setupProxy(projects, certPath, keyPath, domain)

	go func() {
		println("Starting HTTPS proxy server on port 443...")
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			fatal("HTTPS server error: %v", err)
		}
	}()

	// absPath, _ := filepath.Abs(certPath)
	// println("If you encounter certificate errors, trust the certificate with:")
	// printf("security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db %s", absPath)

	sig := <-signalChan

	println("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		printf("HTTP server shutdown error: %v", err)
	}

	if dnsServer != nil {
		if err := dnsServer.ShutdownContext(ctx); err != nil {
			printf("DNS server shutdown error: %v", err)
		}
	}

	for _, p := range projects {
		if p.Cmd != nil && p.Cmd.Process != nil {
			p.Cmd.Process.Signal(sig)
		}
	}
}

func detectProjects(dir string) ([]Project, error) {
	var projects []Project
	basePort := 8000

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %v", dir, err)
	}

	for i, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		projectPath := filepath.Join(dir, entry.Name())
		gitPath := filepath.Join(projectPath, ".git")

		if _, err := os.Stat(gitPath); err == nil {
			projects = append(projects, Project{
				Name: entry.Name(),
				Path: projectPath,
				Port: basePort + i,
			})
		}
	}

	return projects, nil
}

func startProject(p *Project, wg *sync.WaitGroup) {
	defer wg.Done()

	cmd := exec.Command("npm", "run", "dev")
	cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", p.Port), "FORCE_COLOR=1")
	cmd.Dir = p.Path

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		printf("Failed to create stdout pipe for %s: %v", p.Name, err)
		return
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		printf("Failed to create stderr pipe for %s: %v", p.Name, err)
		return
	}

	p.Cmd = cmd
	err = cmd.Start()
	if err != nil {
		printf("Failed to start server for %s: %v", p.Name, err)
		return
	}

	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			printf("[%s] %s", p.Name, cleanLogLine(scanner.Text()))
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			printf("[%s] %s", p.Name, cleanLogLine(scanner.Text()))
		}
	}()

	// Wait for the server to start listening on the assigned port
	serverReady := false
	timeoutSeconds := 5
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for !serverReady {
		select {
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", p.Port), 500*time.Millisecond)
			if err == nil {
				conn.Close()
				serverReady = true
				break
			}
		case <-timeout:
			printf("Error: %s failed to start on port %d within %d seconds", p.Name, p.Port, timeoutSeconds)
			// Attempt to terminate the process if it didn't start properly
			if p.Cmd != nil && p.Cmd.Process != nil {
				p.Cmd.Process.Kill()
			}
			return
		}
	}
}

func startProjects(projects []Project) {
	var wg sync.WaitGroup

	for i := range projects {
		wg.Add(1)
		go startProject(&projects[i], &wg)
	}

	wg.Wait()
}

func setupProxy(projects []Project, certPath, keyPath, domain string) *http.Server {
	projectTargets := make(map[string]*url.URL)

	for _, p := range projects {
		targetURL, err := url.Parse(fmt.Sprintf("http://localhost:%d", p.Port))
		if err != nil {
			printf("Failed to parse URL for project %s: %v", p.Name, err)
			continue
		}

		projectTargets[p.Name] = targetURL
		printf("https://%s.%s → %s", p.Name, domain, targetURL)
	}

	director := func(req *http.Request) {
		host := req.Host

		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}

		var projectName string

		parts := strings.Split(strings.TrimSuffix(host, "."+domain), ".")
		projectName = parts[len(parts)-1]

		target, exists := projectTargets[projectName]
		if !exists {
			printf("No project found for host: %s (project: %s)", host, projectName)
			return
		}

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)

		if target.RawQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
		}
	}

	proxy := &httputil.ReverseProxy{Director: director}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		fatal("Failed to load TLS certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &http.Server{
		Addr:      ":443",
		Handler:   proxy,
		TLSConfig: tlsConfig,
	}

	return server
}

func generateCertificate(certPath, keyPath, domain string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	// Create DNS names for the certificate based on the domain
	dnsNames := []string{
		fmt.Sprintf("*.%s", domain),
		domain,
		fmt.Sprintf("*.*.%s", domain),
	}
	printf("Creating wildcard certificate for *.%s and *.*.%s", domain, domain)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Hostel Local Development"},
			CommonName:   fmt.Sprintf("*.%s", domain),
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return err
	}

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err != nil {
		return err
	}

	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")

	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func fatal(message string, args ...any) {
	if len(args) > 0 {
		message = fmt.Sprintf(message+": %s", args...)
	}
	println(message)
	os.Exit(1)
}

func printf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

func cleanLogLine(str string) string {
	// Keep color codes (SGR - Select Graphic Rendition) which use the 'm' terminator
	// but filter out other ANSI escape sequences

	// This regex matches non-color ANSI sequences:
	// - Cursor movement (A, B, C, D, E, F, G, H)
	// - Clear screen/line (J, K)
	// - Scrolling (S, T)
	// - Cursor position save/restore (s, u)
	// - And others that don't end with 'm'
	nonColorRe := regexp.MustCompile(`\x1B\[[0-9;]*[ABCDEFGHJKSTsuhl]`)
	str = nonColorRe.ReplaceAllString(str, "")

	// Filter out OSC (Operating System Command) sequences
	// These often look like \x1B]0;Some terminal title\x07
	oscRe := regexp.MustCompile(`\x1B\][0-9].*?(\x07|\x1B\\)`)
	str = oscRe.ReplaceAllString(str, "")

	// Remove any other control characters that might cause issues
	// but keep tabs, newlines, carriage returns, and ESC (for color codes)
	clean := make([]rune, 0, len(str))
	for _, r := range str {
		// Keep:
		// - Printable characters (r >= 32)
		// - Tab (9), Newline (10), Carriage return (13)
		// - ESC (27) for ANSI color sequences
		if r >= 32 || r == '\t' || r == '\n' || r == '\r' || r == 27 {
			clean = append(clean, r)
		}
	}

	return string(clean)
}
