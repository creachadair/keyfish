module github.com/creachadair/keyfish

require (
	github.com/creachadair/atomicfile v0.4.2
	github.com/creachadair/command v0.2.12
	github.com/creachadair/flax v0.1.0
	github.com/creachadair/getpass v0.4.0
	github.com/creachadair/mds v0.31.0
	github.com/creachadair/otp v0.5.5
	github.com/fsnotify/fsnotify v1.10.1
	github.com/google/go-cmp v0.7.0
	golang.org/x/crypto v0.57.0
	golang.org/x/term v0.46.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	github.com/creachadair/wirepb v0.0.0-20260803044834-54eb959db0a7 // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
	honnef.co/go/tools v0.8.2 // indirect
)

go 1.26.0

tool honnef.co/go/tools/staticcheck

retract v0.13.14 // published mistakenly
