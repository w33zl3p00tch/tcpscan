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

	var slice []int
	var wg0 sync.WaitGroup
	var wg1 sync.WaitGroup
	queue := make(chan int)

	wg0.Add(ports)

	for port := 0; port < ports; port++ {
		go func(p int) {
			defer wg0.Done()
			checkPort := connTcp(host, uint16(p), timeout)
			if checkPort {
				queue <- p
			}
		}(port)
	}

	wg1.Add(1)
	go func() {
		defer wg1.Done()
		for t := range queue {
			slice = append(slice, t)
		}
	}()

	wg0.Wait()
	close(queue)
	wg1.Wait()
	sort.Ints(slice)

	for i := range slice {
		fmt.Println(slice[i])
	}
}

func connTcp(host string, port uint16, t time.Duration) bool {
	for i := 0; i < 3; i++ {
		if connection, err := net.DialTimeout("tcp",
			host+":"+fmt.Sprintf("%d", port), t); err == nil {
			connection.Close()
			return true // we have a response
		}
	}
	return false
}
