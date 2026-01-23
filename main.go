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

	"github.com/fsnotify/fsnotify"
)

type Project struct {
	Name string
	Path string
	Port int
	Cmd  *exec.Cmd
}

type ProxyTargets struct {
	sync.RWMutex
	targets map[string]*url.URL
}

func (pt *ProxyTargets) Get(name string) (*url.URL, bool) {
	pt.RLock()
	defer pt.RUnlock()
	target, ok := pt.targets[name]
	return target, ok
}

func (pt *ProxyTargets) Update(projects []Project, domain string) {
	pt.Lock()
	defer pt.Unlock()
	pt.targets = make(map[string]*url.URL)
	for _, p := range projects {
		targetURL, err := url.Parse(fmt.Sprintf("http://localhost:%d", p.Port))
		if err != nil {
			printf("Failed to parse URL for project %s: %v", p.Name, err)
			continue
		}
		pt.targets[p.Name] = targetURL
		printf("https://%s.%s → %s", p.Name, domain, targetURL)
	}
}

type ServiceRegistry struct {
	sync.RWMutex
	services map[string]bool
}

func (r *ServiceRegistry) Has(name string) bool {
	r.RLock()
	defer r.RUnlock()
	_, exists := r.services[name]
	return exists
}

func (r *ServiceRegistry) Update(config Config) {
	r.Lock()
	defer r.Unlock()
	r.services = make(map[string]bool)
	for name := range config {
		r.services[name] = true
	}
}

func stopProjects(projects []Project) {
	for _, p := range projects {
		if p.Cmd != nil && p.Cmd.Process != nil {
			syscall.Kill(-p.Cmd.Process.Pid, syscall.SIGTERM)
			p.Cmd.Wait()
		}
	}
}

func setTerminalTitle(title string) {
	fmt.Printf("\033]0;%s\007", title)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "add":
			handleAddCommand(os.Args[2:])
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}

	runDaemon()
}

func printUsage() {
	fmt.Println(`hostel - A simple reverse proxy for local development

Usage:
    hostel              Start the proxy server
    hostel add [name]   Add current directory to config
                        Uses directory name if [name] not provided

Options:
    -domain string      Custom domain to use (default: hostel.dev)
    -h, --help          Show this help message

Config file: ~/.config/hostel/config.toml`)
}

func handleAddCommand(args []string) {
	cwd, err := os.Getwd()
	if err != nil {
		fatal("Failed to get current directory: %v", err)
	}

	var serviceName string
	if len(args) > 0 && args[0] != "" {
		serviceName = args[0]
	} else {
		serviceName = filepath.Base(cwd)
	}

	if !isValidServiceName(serviceName) {
		fatal("Invalid service name '%s'. Use only letters, numbers, hyphens, and underscores.", serviceName)
	}

	config, err := loadConfig()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	if existing, exists := config[serviceName]; exists {
		if existing.Path == cwd {
			printf("Service '%s' already configured with path %s", serviceName, cwd)
			return
		}
		fatal("Service '%s' already exists with path: %s\nUse a different name or remove the existing entry.", serviceName, existing.Path)
	}

	config[serviceName] = ServiceConfig{
		Path: cwd,
	}

	if err := saveConfig(config); err != nil {
		fatal("Failed to save config: %v", err)
	}

	printf("Added '%s' -> %s", serviceName, cwd)

	path, _ := configPath()
	printf("Config saved to %s", path)
}

func runDaemon() {
	println(`
 _               _       _
| |__   ___  ___| |_ ___| |
| '_ \ / _ \/ __| __/ _ \ |
| | | | (_) \__ \ ||  __/ |
|_| |_|\___/|___/\__\___|_|

A simple reverse proxy for local development
`)

	setTerminalTitle("hostel")

	domainFlag := flag.String("domain", "hostel.dev", "Custom domain to use for projects")
	flag.Parse()

	domain := *domainFlag

	config, err := loadConfig()
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	if len(config) == 0 {
		path, _ := configPath()
		fatal("No services configured.\n\nAdd services with:\n    cd /path/to/project && hostel add\n\nOr manually edit: %s", path)
	}

	if err := validateConfig(config); err != nil {
		fatal("Config error: %v", err)
	}

	projects := configToProjects(config)

	configDir, _ := configPath()
	configDir = filepath.Dir(configDir)
	certPath, keyPath := filepath.Join(configDir, domain+".crt"), filepath.Join(configDir, domain+".key")
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

	serviceRegistry := &ServiceRegistry{services: make(map[string]bool)}
	serviceRegistry.Update(config)

	dnsServer := StartDNSServer(domain, serviceRegistry.Has)

	proxyTargets := &ProxyTargets{targets: make(map[string]*url.URL)}
	proxyTargets.Update(projects, domain)
	startProjects(projects, domain)

	server := setupProxy(proxyTargets, certPath, keyPath, domain)

	go func() {
		println("Starting HTTPS proxy server on port 443...")
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			fatal("HTTPS server error: %v", err)
		}
	}()

	reloadChan := make(chan bool, 1)
	go watchConfig(reloadChan)

	for {
		select {
		case <-reloadChan:
			println("Config changed, reloading...")
			stopProjects(projects)

			config, err = loadConfig()
			if err != nil {
				printf("Failed to reload config: %v", err)
				continue
			}

			if err := validateConfig(config); err != nil {
				printf("Config error: %v", err)
				continue
			}

			projects = configToProjects(config)
			serviceRegistry.Update(config)
			proxyTargets.Update(projects, domain)
			startProjects(projects, domain)
			println("Reload complete")

		case sig := <-signalChan:
			println("Shutting down...")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

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

			cancel()
			return
		}
	}
}

func watchConfig(reloadChan chan<- bool) {
	path, err := configPath()
	if err != nil {
		printf("Failed to get config path for watcher: %v", err)
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		printf("Failed to create file watcher: %v", err)
		return
	}
	defer watcher.Close()

	dir := filepath.Dir(path)
	if err := watcher.Add(dir); err != nil {
		printf("Failed to watch config directory: %v", err)
		return
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Name == path && (event.Op&fsnotify.Write != 0 || event.Op&fsnotify.Create != 0) {
				select {
				case reloadChan <- true:
				default:
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			printf("File watcher error: %v", err)
		}
	}
}

func hasDevTarget(projectPath string) bool {
	makefilePath := filepath.Join(projectPath, "Makefile")
	if !fileExists(makefilePath) {
		return false
	}

	file, err := os.Open(makefilePath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "dev:") {
			return true
		}
	}

	return false
}

func startProject(p *Project, domain string, wg *sync.WaitGroup) {
	defer wg.Done()

	host := fmt.Sprintf("%s.%s", p.Name, domain)
	env := append(os.Environ(),
		fmt.Sprintf("PORT=%d", p.Port),
		fmt.Sprintf("__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=%s", host),
		"FORCE_COLOR=1",
	)

	var cmd *exec.Cmd
	if hasDevTarget(p.Path) {
		cmd = exec.Command("make", "dev")
		cmd.Env = env
	} else {
		cmd = exec.Command("npm", "run", "dev")
		cmd.Env = env
	}
	cmd.Dir = p.Path
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

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
			printf("[%s:%d] %s", p.Name, p.Port, cleanLogLine(scanner.Text()))
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			printf("[%s:%d] %s", p.Name, p.Port, cleanLogLine(scanner.Text()))
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
			// Kill entire process group
			if p.Cmd != nil && p.Cmd.Process != nil {
				syscall.Kill(-p.Cmd.Process.Pid, syscall.SIGTERM)
			}
			return
		}
	}
}

func startProjects(projects []Project, domain string) {
	var wg sync.WaitGroup

	for i := range projects {
		wg.Add(1)
		go startProject(&projects[i], domain, &wg)
	}

	wg.Wait()
}

func setupProxy(proxyTargets *ProxyTargets, certPath, keyPath, domain string) *http.Server {
	director := func(req *http.Request) {
		host := req.Host

		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}

		parts := strings.Split(strings.TrimSuffix(host, "."+domain), ".")
		projectName := parts[len(parts)-1]

		target, exists := proxyTargets.Get(projectName)
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

func fatal(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
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
