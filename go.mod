module github.com/creachadair/keyfish

require (
	github.com/creachadair/atomicfile v0.4.2
	github.com/creachadair/command v0.2.11
	github.com/creachadair/flax v0.0.6
	github.com/creachadair/getpass v0.3.6
	github.com/creachadair/mds v0.30.5
	github.com/creachadair/otp v0.5.5
	github.com/fsnotify/fsnotify v1.10.1
	github.com/google/go-cmp v0.7.0
	golang.org/x/crypto v0.55.0
	golang.org/x/term v0.45.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/creachadair/wirepb v0.0.0-20260803044834-54eb959db0a7 // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/tools v0.44.1-0.20260420230617-19499e7caabc // indirect
	honnef.co/go/tools v0.8.1 // indirect
)

go 1.26.0

tool honnef.co/go/tools/staticcheck

retract v0.13.14 // published mistakenly
