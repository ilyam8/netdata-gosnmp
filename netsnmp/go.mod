module github.com/netdata/gosnmp/netsnmp

go 1.27.0

require (
	github.com/google/go-cmp v0.7.0
	github.com/google/gopacket v1.1.19
	github.com/netdata/gosnmp v0.0.0-00010101000000-000000000000
)

require (
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
)

replace github.com/netdata/gosnmp => ../
