module github.com/creachadair/keyfish

require (
	github.com/creachadair/atomicfile v0.4.1
	github.com/creachadair/command v0.2.0
	github.com/creachadair/flax v0.0.5
	github.com/creachadair/getpass v0.3.0
	github.com/creachadair/mds v0.26.0
	github.com/creachadair/otp v0.5.4
	github.com/fsnotify/fsnotify v1.9.0
	github.com/google/go-cmp v0.7.0
	golang.org/x/crypto v0.48.0
	golang.org/x/term v0.40.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/creachadair/wirepb v0.0.0-20260218173010-2346782bc0a5 // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/tools v0.40.1-0.20260108161641-ca281cf95054 // indirect
	honnef.co/go/tools v0.7.0 // indirect
)

go 1.25.0

tool honnef.co/go/tools/staticcheck

retract v0.13.14 // published mistakenly
