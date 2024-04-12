module github.com/qubic/go-schnorrq

go 1.22

//TODO: remove once circl PR gets accepted
replace github.com/cloudflare/circl v1.3.7 => /home/linckode/Projects/qubic/circl

require (
	github.com/cloudflare/circl v1.3.7
	github.com/google/go-cmp v0.6.0
	github.com/pkg/errors v0.9.1
	github.com/qubic/go-node-connector v0.4.2
)

require golang.org/x/sys v0.15.0 // indirect
