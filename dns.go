// hostel - DNS server with service-aware routing
package main

import (
	"context"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var port = "55353"

// upstreamResolver forwards queries to Google DNS to avoid recursion
// when the system resolver points back to hostel
var upstreamResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, "udp", "8.8.8.8:53")
	},
}

// StartDNSServer starts a DNS server that:
// - Returns 127.0.0.1 for known services under the given domain
// - Forwards other queries to upstream DNS
func StartDNSServer(domain string, hasService func(name string) bool) *dns.Server {
	dnsServer := &dns.Server{
		Addr: ":" + port,
		Net:  "udp",
	}

	domainSuffix := "." + domain

	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
				qname := strings.TrimSuffix(q.Name, ".")

				if strings.HasSuffix(qname, domainSuffix) {
					// Query is for our domain (e.g., myapp.hostel.dev)
					subdomain := strings.TrimSuffix(qname, domainSuffix)
					parts := strings.Split(subdomain, ".")
					serviceName := parts[len(parts)-1]

					// "test" is a special subdomain that always resolves to 127.0.0.1
					// Used to verify DNS is working during startup
					if serviceName == "test" || (serviceName != "" && hasService(serviceName)) {
						// Known service or test: return 127.0.0.1
						rr := &dns.A{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    60,
							},
							A: net.ParseIP("127.0.0.1").To4(),
						}
						m.Answer = append(m.Answer, rr)
					} else {
						// Unknown service under our domain: NXDOMAIN
						m.Rcode = dns.RcodeNameError
					}
				} else if qname == domain {
					// Bare domain (e.g., "hostel.dev"): return 127.0.0.1
					rr := &dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						A: net.ParseIP("127.0.0.1").To4(),
					}
					m.Answer = append(m.Answer, rr)
				} else {
					// Not our domain: forward to upstream DNS
					answers := forwardQuery(qname, q.Name)
					m.Answer = append(m.Answer, answers...)
				}
			}
		}

		w.WriteMsg(m)
	})

	go func() {
		if err := dnsServer.ListenAndServe(); err != nil {
			fatal("Failed to start DNS server: %v", err)
		}
	}()

	// Brief pause to let DNS server start
	time.Sleep(100 * time.Millisecond)

	// Verify DNS is working by looking up test.{domain}
	// The "test" subdomain always resolves to 127.0.0.1
	testHost := "test." + domain
	ips, err := net.LookupHost(testHost)

	if err != nil || !slices.Contains(ips, "127.0.0.1") {
		// Extract TLD from domain (e.g., "hostel.dev" -> "dev")
		parts := strings.Split(domain, ".")
		tld := parts[len(parts)-1]

		fatal(`
DNS problem: *.%s does not seem to resolve to 127.0.0.1.

You can fix this by running:

    $ sudo mkdir -p /etc/resolver && echo -e "nameserver 127.0.0.1\nport %s" | sudo tee /etc/resolver/%s
`, domain, port, tld)
	}

	return dnsServer
}

func forwardQuery(hostname, dnsName string) []dns.RR {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := upstreamResolver.LookupIP(ctx, "ip4", hostname)
	if err != nil {
		return nil
	}

	var answers []dns.RR
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   dnsName,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: ipv4,
			}
			answers = append(answers, rr)
		}
	}
	return answers
}
