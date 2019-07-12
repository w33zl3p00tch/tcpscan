/*
tcpscan - a simple TCP port scanner

(c) 2019 Manuel Iwansky

tcpscan is licensed under a BSD style license as stated in the LICENSE file
that you should have received along with this source code.
*/
package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var help = `
This is a simple TCP port scanner. It checks all TCP ports and
prints the ports that it could connect to.

Usage:
tcpscan TARGET

where TARGET can be an IP address or a hostname

"tcpscan -h" prints this help text.


Warning: Open ports are determined by explicitly connecting to
them. If you need anything more stealthy, this is not the right
tool for you.

tcpscan is licensed under a BSD style license as stated in the
LICENSE file that should have come with this software.
Please don't use this tool for questionable or illegal purposes.
`

func main() {
	if len(os.Args) == 1 || os.Args[1] == "-h" {
		fmt.Println(help)
		os.Exit(0)
	}

	host := os.Args[1]
	timeout := time.Second * 5
	ports := 65536

	var results []int
	var wg0 sync.WaitGroup
	var wg1 sync.WaitGroup
	queue := make(chan int)

	wg0.Add(ports)

	for port := 0; port < ports; port++ {
		go func(p int) {
			defer wg0.Done()
			checkPort := connTCP(host, uint16(p), timeout)
			if checkPort {
				queue <- p
			}
		}(port)
	}

	wg1.Add(1)
	go func() {
		defer wg1.Done()
		for t := range queue {
			results = append(results, t)
		}
	}()

	wg0.Wait()
	close(queue)
	wg1.Wait()
	sort.Ints(results)

	for i := range results {
		fmt.Println(results[i])
	}
}

// connTCP tries to connect to a port until the connection is refused or accepted.
func connTCP(host string, port uint16, t time.Duration) bool {
	retry := time.Second / 2
	tgt := fmt.Sprintf("%s:%d", host, port)

	for {
		conn, err := net.DialTimeout("tcp", tgt, t)
		if err != nil {
			if strings.Contains(err.Error(), "too many open files") {
				// try again later. Could be avoided by reading the
				// machine's ulimit for file handles and queueing the
				// goroutines accordingly.
				time.Sleep(retry)
				continue
			} else if strings.Contains(err.Error(), "device or resource busy") {
				time.Sleep(retry)
				continue
			} else if strings.Contains(err.Error(), "can't assign requested address") {
				// maybe IPv6 is disabled on this host
				return false
			} else if strings.Contains(err.Error(), "requested address is not valid") {
				return false
			} else if strings.Contains(err.Error(), "i/o timeout") {
				time.Sleep(retry)
				continue
			} else if strings.Contains(err.Error(), "connection refused") {
				// nope. That port is closed.
				return false
			} else {
				// some error we haven't yet encountered (firewall?)
				//fmt.Println(err)
				//fmt.Println("Maybe this is a firewall/QOS issue. Aborting.")
				//os.Exit(1)
				return false
			}
		}

		if err := conn.Close(); err != nil {
			p := fmt.Sprintf("%d", port)
			warn := "Warning: error on closing connection to port " + p
			os.Stderr.WriteString(warn)
		}

		return true // Yes, this is an open port.
	}
}
