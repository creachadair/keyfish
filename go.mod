module github.com/creachadair/keyfish

require (
	github.com/creachadair/atomicfile v0.4.0
	github.com/creachadair/command v0.2.0
	github.com/creachadair/flax v0.0.5
	github.com/creachadair/getpass v0.3.0
	github.com/creachadair/mds v0.25.6
	github.com/creachadair/otp v0.5.2
	github.com/fsnotify/fsnotify v1.9.0
	github.com/google/go-cmp v0.7.0
	golang.org/x/crypto v0.42.0
	golang.org/x/term v0.35.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/creachadair/wirepb v0.0.0-20251002031904-78c565c2f93e // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.23.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/tools v0.30.0 // indirect
	honnef.co/go/tools v0.6.1 // indirect
)

go 1.24.0

tool honnef.co/go/tools/staticcheck

retract v0.13.14 // published mistakenly
