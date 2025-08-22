package main

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

type DNSResult struct {
	Level       int
	Domain      string
	Authorities []AuthorityServer
	Error       string
}

type AuthorityServer struct {
	Hostname     string
	IPs          net.IP
	Responses    []string
	QueryResults []QueryResult
	Error        string
}

type QueryResult struct {
	ServerIP  string
	Response  string
	NextLevel *DNSResult
	Error     string
}

var (
	dnsServer string
	dnstype   string
	iptype    string
	rootHints = []string{
		"a.root-servers.net.",
		"b.root-servers.net.", "c.root-servers.net.",
		"d.root-servers.net.", "e.root-servers.net.", "f.root-servers.net.",
		"g.root-servers.net.", "h.root-servers.net.", "i.root-servers.net.",
		"j.root-servers.net.", "k.root-servers.net.", "l.root-servers.net.",
		"m.root-servers.net.",
	}
)

func main() {
	flag.StringVar(&dnsServer, "dns", "8.8.8.8", "DNS server to use for initial queries")
	flag.StringVar(&dnstype, "dnstype", "a/aaaa", "DNS type to test (a, aaaa)")
	flag.StringVar(&iptype, "iptype", "4/6", "IP version to test (4, 6, all)")
	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Println("Usage: mdig [-dns server] [-dnstype a|aaaa] [-iptype 4|6|all] <domain>")
		return
	}

	domain := flag.Arg(0)
	fmt.Println("Tracing DNS for domain: ", domain)
	results := traceDNS(domain)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Level < results[j].Level
	})
	for _, res := range results {
		printDNSResult(res)
	}
}

func traceDNS(domain string) []DNSResult {
	var results []DNSResult
	prevServers := rootHints
	i := 0
	var qtypes uint16
	switch dnstype {
	case "a":
		qtypes = dns.TypeA
	case "aaaa":
		qtypes = dns.TypeAAAA
	default:
		qtypes = dns.TypeA
	}
	fmt.Printf("Using DNS server: %s, Query type: %d\n", dnsServer, qtypes)
	eTLDPlusOne, _ := publicsuffix.EffectiveTLDPlusOne(domain)
	parts := strings.Split(eTLDPlusOne, ".")
	if len(parts) < 2 {
		result := DNSResult{Error: "no authority servers found"}
		results = append(results, result)
		return results
	}
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	for {
		if len(prevServers) == 0 {
			break
		}
		i++
		result := DNSResult{
			Level:  i,
			Domain: domain,
		}
		fmt.Printf("Processing level %d for domain: %s\n", i, domain)
		authorities, nextServers, err := getAuthorities(domain, prevServers, qtypes)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			return results
		}

		if len(authorities) == 0 {
			result.Error = "no authority servers found"
			results = append(results, result)
			return results
		}

		result.Authorities = authorities
		results = append(results, result)
		prevServers = nextServers

	}
	return results
}

func printDNSResult(res DNSResult) {
	fmt.Printf("Level %d: %s\n", res.Level, res.Domain)
	if res.Error != "" {
		fmt.Printf("  ! Error: %s\n", res.Error)
	}

	for _, auth := range res.Authorities {
		fmt.Printf("  ├─ NS: %s\n", auth.Hostname)
		fmt.Printf("  │   ├─ NS IP: %s\n", auth.IPs)

		if len(auth.Responses) > 0 {
			fmt.Printf("  │   ├─ Responses:\n")
			for _, resp := range auth.Responses {
				fmt.Printf("  │   │   ├─ %s\n", resp)
			}
		} else {
			// fmt.Printf("  │   ├─ Responses:\n")
			fmt.Printf("  │   ├─ Responses: \n")
			fmt.Printf("  │   │   ├─ %s\n", "No responses found")
		}

		if len(auth.QueryResults) > 0 {
			fmt.Printf("  │   └─ Query Results:\n")
			for _, qr := range auth.QueryResults {
				fmt.Printf("  │       ├─ %+v\n", qr) // 根据QueryResult结构补充
			}
		}
		if auth.Error != "" {
			fmt.Printf("  │       ├─ %s\n", auth.Error)
		}

	}
	fmt.Println("───")
}

func getAuthorities(domain string, servers []string, dnstype uint16) ([]AuthorityServer, []string, error) {
	var authServers []AuthorityServer
	var nextNS []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 10) // 限制并发数为10
	for _, server := range servers {
		// time.Sleep(1 * time.Second)
		wg.Add(1)
		sem <- struct{}{}
		go func(srv string) {
			defer wg.Done()
			defer func() { <-sem }()
			auth := AuthorityServer{Hostname: srv}
			ips, err := lookupSpecificIP(srv)
			if err != nil {
				auth.Error = "IP lookup failed: " + err.Error()
				mu.Lock()
				authServers = append(authServers, auth)
				mu.Unlock()
				return
			}
			for _, ip := range ips {
				var nextNS_local []string
				var domainResult_local []string
				resp, err := queryAuthorities(domain, ip.String(), dnstype)
				auth.IPs = ip
				if err != nil {
					auth.Error = "query failed: " + err.Error()
					mu.Lock()
					authServers = append(authServers, auth)
					mu.Unlock()
					continue
				}

				for _, rr := range resp {
					switch r := rr.(type) {
					case *dns.NS:
						nextNS_local = append(nextNS_local, r.Ns)
						nextNS = append(nextNS, r.Ns)
					case *dns.A:
						domainResult_local = append(domainResult_local, r.A.String())
					case *dns.AAAA:
						domainResult_local = append(domainResult_local, r.AAAA.String())
					case *dns.CNAME:
						domainResult_local = append(domainResult_local, r.Target)
					}
				}
				mu.Lock()
				domainResult_local = uniqueStrings(domainResult_local)
				auth.Responses = append(nextNS_local, domainResult_local...)
				authServers = append(authServers, auth)
				mu.Unlock()
			}
		}(server)
	}

	wg.Wait()
	return authServers, uniqueStrings(nextNS), nil
}

func queryAuthorities(domain, server string, dnstype uint16) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(domain, dnstype)

	c := new(dns.Client)
	c.Timeout = 3 * time.Second

	r, _, err := c.Exchange(m, net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, err
	}

	if len(r.Answer) > 0 {
		return r.Answer, nil
	}
	return r.Ns, nil
}

func lookupSpecificIP(hostname string) ([]net.IP, error) {
	var qtypes []uint16
	switch iptype {
	case "4":
		qtypes = []uint16{dns.TypeA}
	case "6":
		qtypes = []uint16{dns.TypeAAAA}
	case "all":
		qtypes = []uint16{dns.TypeA, dns.TypeAAAA}
	default:
		qtypes = []uint16{dns.TypeCNAME}
	}

	var ips []net.IP
	for _, qtype := range qtypes {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(hostname), qtype)
		c := new(dns.Client)
		resp, _, err := c.Exchange(m, net.JoinHostPort(dnsServer, "53"))
		if err != nil {
			continue
		}
		for _, ans := range resp.Answer {
			switch record := ans.(type) {
			case *dns.A:
				ips = append(ips, record.A)
			case *dns.AAAA:
				ips = append(ips, record.AAAA)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP found for %s", hostname)
	}
	return ips, nil
}
func uniqueStrings(input []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, s := range input {
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}
