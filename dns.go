// hostel - Simple DNS server implementation
package main

import (
	"net"
	"slices"

	"github.com/miekg/dns"
)

var port = "55353"

// StartDNSServer starts a DNS server that responds to all queries with 127.0.0.1
// Returns the DNS server instance
func StartDNSServer() *dns.Server {
	dnsServer := &dns.Server{
		Addr: ":" + port,
		Net:  "udp",
	}

	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
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
			}
		}

		w.WriteMsg(m)
	})

	go func() {
		if err := dnsServer.ListenAndServe(); err != nil {
			fatal("Failed to start DNS server: %v", err)
		}
	}()

	ips, err := net.LookupHost("foobar.localhost")

	if err != nil || !slices.Contains(ips, "127.0.0.1") {
		fatal(`
DNS problem: *.localhost does not seem to resolve to 127.0.0.1.

You may be able to fix this by running:

	$ sudo mkdir -p /etc/resolver && echo -e "nameserver 127.0.0.1\nport 55353" | sudo tee /etc/resolver/localhost
`)
	}

	return dnsServer
}
