# tcpscan

This is a simple TCP port scanner. It checks all TCP ports and prints the port numbers that it could connect to.


## Usage:

```tcpscan TARGET```

where ```TARGET``` can be an IP address or a hostname

```tcpscan -h``` prints a short help text.


## Installation

```go get github.com/w33zl3p00tch/tcpscan```

To build a smaller binary, you can build it like this:

```go build -ldflags "-s -w" tcpscan.go```

Additionally, you can compress it with UPX: https://upx.github.io


## License

tcpscan is licensed under a BSD style license as stated in the LICENSE file.
Please don't use this tool for questionable or illegal purposes.
