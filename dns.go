// hostel - Simple DNS server implementation
package main

import (
	"log"
	"net"

	"github.com/miekg/dns"
)

// StartDNSServer starts a DNS server that responds to all queries with 127.0.0.1
// Returns the DNS server instance
func StartDNSServer() *dns.Server {
	dnsServer := &dns.Server{
		Addr: ":53",
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
			log.Printf("Failed to start DNS server: %v", err)
		}
	}()
	
	return dnsServer
}
