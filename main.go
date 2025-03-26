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
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Project struct {
	Name string
	Path string
	Port int
	Cmd  *exec.Cmd
}

func main() {
	log.Println("Starting hostel - local development proxy server")

	// Get the directory to scan (default to current directory)
	scanDir := "."
	if len(os.Args) > 1 {
		scanDir = os.Args[1]
	}

	projects, err := detectProjects(scanDir)
	if err != nil {
		log.Fatalf("Failed to detect projects: %v", err)
	}

	if len(projects) == 0 {
		log.Fatalf("No projects found in the current directory")
	}

	certPath, keyPath := "hostel.crt", "hostel.key"
	if !fileExists(certPath) || !fileExists(keyPath) {
		log.Println("Generating TLS certificate...")
		err = generateCertificate(certPath, keyPath)
		if err != nil {
			log.Fatalf("Failed to generate TLS certificate: %v", err)
		}
		log.Println("TLS certificate generated successfully")
	}

	// Setup signal handling
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Start DNS server
	dnsServer := StartDNSServer()

	// Start project servers
	startProjects(projects)

	// Create HTTP server but don't start it yet
	server := setupProxy(projects, certPath, keyPath)

	// Start HTTP server in a goroutine
	go func() {
		log.Println("Starting HTTPS proxy server on port 443...")
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()

	absPath, _ := filepath.Abs(certPath)
	log.Println("If you encounter certificate errors, trust the certificate with:")
	log.Printf("security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db %s", absPath)

	// Wait for termination signal
	sig := <-signalChan
	// log.Printf("Received signal: %v, shutting down...", sig)
	println("Shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	if err := dnsServer.ShutdownContext(ctx); err != nil {
		log.Printf("DNS server shutdown error: %v", err)
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
	cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", p.Port))
	cmd.Dir = p.Path

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("Failed to create stdout pipe for %s: %v", p.Name, err)
		return
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Printf("Failed to create stderr pipe for %s: %v", p.Name, err)
		return
	}

	p.Cmd = cmd
	err = cmd.Start()
	if err != nil {
		log.Printf("Failed to start server for %s: %v", p.Name, err)
		return
	}

	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			fmt.Printf("[%s] %s\n", p.Name, scanner.Text())
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			fmt.Printf("[%s] %s\n", p.Name, scanner.Text())
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
				log.Printf("Server for %s is listening on port %d", p.Name, p.Port)
				break
			}
		case <-timeout:
			log.Printf("Error: %s failed to start on port %d within %d seconds", p.Name, p.Port, timeoutSeconds)
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

func setupProxy(projects []Project, certPath, keyPath string) *http.Server {
	projectTargets := make(map[string]*url.URL)

	for _, p := range projects {
		targetURL, err := url.Parse(fmt.Sprintf("http://localhost:%d", p.Port))
		if err != nil {
			log.Printf("Failed to parse URL for project %s: %v", p.Name, err)
			continue
		}

		projectTargets[p.Name] = targetURL
		log.Printf("https://%s.localhost → %s", p.Name, targetURL)
	}

	director := func(req *http.Request) {
		host := req.Host

		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}

		// Extract project name from hostname
		// This will match both project.localhost and any subdomain.project.localhost
		parts := strings.Split(host, ".")
		var projectName string

		if len(parts) >= 2 && parts[len(parts)-1] == "localhost" {
			projectName = parts[len(parts)-2]
		}

		target, exists := projectTargets[projectName]
		if !exists {
			log.Printf("No project found for host: %s (project: %s)", host, projectName)
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
		log.Fatalf("Failed to load TLS certificate: %v", err)
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

func generateCertificate(certPath, keyPath string) error {
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

	dnsNames := []string{"*.localhost", "localhost", "*.*.localhost"}
	log.Printf("Creating wildcard certificate for *.localhost and *.*.localhost")

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Hostel Local Development"},
			CommonName:   "*.localhost",
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
