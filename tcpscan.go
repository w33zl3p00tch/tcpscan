/*
tcpscan - a simple TCP port scanner

(c) 2019 Manuel Iwansky

tcpscan is licensed under a BSD style license as stated in the LICENSE file
that you should have received along with this source code.
*/
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
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

var (
	queue chan int // queue for storing found open ports
)

type portScanner struct {
	host string
	lock *semaphore.Weighted
}

func main() {
	if len(os.Args) == 1 || os.Args[1] == "-h" {
		fmt.Println(help)
		os.Exit(0)
	}

	hostOrIp := os.Args[1] // TODO: make name resolution once.
	timeout := time.Second / 2
	first := 1
	ports := 65536

	limit := 512 // limit active goroutines to this.
	// TODO: portable reading of equivalent of `ulimit -n`

	var results []int
	var wg sync.WaitGroup
	var wgQueue sync.WaitGroup
	queue = make(chan int)

	// read queue in the background
	wgQueue.Add(1)
	go func() {
		defer wgQueue.Done()
		for t := range queue {
			results = append(results, t)
		}
	}()

	// do the scan
	ps := &portScanner{
		host: hostOrIp,
		lock: semaphore.NewWeighted(int64(limit)),
	}
	ps.Run(first, ports, timeout, wg)

	wg.Wait()
	close(queue)
	wgQueue.Wait()
	sort.Ints(results)

	for i := range results {
		fmt.Println(results[i])
	}
}

// connTCP tries to connect to a port until the connection is refused or accepted.
func connTCP(host string, port uint16, t time.Duration) bool {
	retry := time.Second / 2
	retryCount := 1
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
		action = "refused"
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

// Run a port scan.
func (ps *portScanner) Run(f, l int, timeout time.Duration, wg sync.WaitGroup) {
	for port := f; port < l; port++ {
		ps.lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(p int) {
			defer ps.lock.Release(1)
			defer wg.Done()
			checkPort := connTCP(ps.host, uint16(p), timeout)
			if checkPort {
				queue <- p
			}
		}(port)
	}
}
