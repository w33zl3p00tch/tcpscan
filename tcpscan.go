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
	timeout := time.Second / 2
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
	retryCount := 3
	retryCounter := 0
	tgt := fmt.Sprintf("%s:%d", host, port)

	for {
		conn, err := net.DialTimeout("tcp", tgt, t)
		if err != nil {
			switch action := checkConnErr(err); action {
			case "retry":
				time.Sleep(retry)
				continue
			case "refused":
				if retryCounter < retryCount {
					retryCounter++
					time.Sleep(retry)
					continue
				} else {
					// nope. That port is closed.
					return false
				}
			default:
				//fmt.Println(err)
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

// checkConnErr returns a proposed action according to the error.
func checkConnErr(err error) string {
	chk := strings.Contains
	var action string
	errMsg := err.Error()

	switch {
	case chk(errMsg, "connection refused"):
		action = "refused"
	case chk(errMsg, "i/o timeout"):
		action = "retry"
	case chk(errMsg, "requested address is not valid"):
		action = "invalid_addr"
	case chk(errMsg, "can't assign requested address"):
		action = "addr_unassignable"
	case chk(errMsg, "device or resource busy"):
		action = "retry"
	case chk(errMsg, "too many open files"):
		action = "retry"
	default:
		action = "action_not_handled"
	}

	return action
}
