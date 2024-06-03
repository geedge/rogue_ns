package main

import (
	"flag"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func rogue_delegation(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.Authoritative = true

	qname := m.Question[0].Name
	qtype := m.Question[0].Qtype
	subdomain := strings.ToLower(strings.Split(qname, ".")[0])
	if qtype == dns.TypeA {
		if subdomain == "ns1" || subdomain == "ns2" {
			resp := &dns.A{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
				A:   net.ParseIP(CONFIG_NS),
			}
			m.Answer = append(m.Answer, resp)
		} else if strings.Contains(subdomain, "rogue") {
			var ns_target string
			var resp *dns.NS
			for i := 0; i < 5; i++ {
				ns_target = strings.Join([]string{subdomain + strconv.Itoa(i), CONFIG_SLD}, ".")
				resp = &dns.NS{
					Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 10},
					Ns:  dns.Fqdn(ns_target),
				}
				m.Ns = append(m.Ns, resp)
			}
		} else {
			m.MsgHdr.Rcode = dns.RcodeNameError
		}
	} else {
		m.MsgHdr.Rcode = dns.RcodeNameError
	}
	w.WriteMsg(m)
}

var CONFIG_SLD string
var CONFIG_NS string

func main() {
	flag.StringVar(&CONFIG_NS, "ns", "8.8.8.8", "nameserver ip address")
	flag.StringVar(&CONFIG_SLD, "sld", "", "configure sld for rogue server")
	flag.Parse()
	if CONFIG_SLD == "" {
		panic("Please configure the SLD for the echo dns server!\n")
	}
	dns.HandleFunc(dns.Fqdn(CONFIG_SLD), rogue_delegation)
	server := &dns.Server{Addr: ":53", Net: "udp"}
	if err := server.ListenAndServe(); err != nil {
		println("Failed to set up the rogue server")
		panic(err)
	}
}
