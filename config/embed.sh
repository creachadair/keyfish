#!/bin/sh
set -euo pipefail

readonly cfpath="${KEYFISH_CONFIG:=}"

# If no config file was specified, create an empty filesystem.
if [[ -z "$cfpath" ]] ; then
    echo "-- No static config file is defined, using ambient defaults" 1>&2
    cat >static.go <<EOF
// Code generated by $(basename $0). DO NOT EDIT.

package config

// No static configuration is defined. This file is a placeholder
// to silence an error from go generate.
EOF
    exit 0
fi

echo "-- Embedding static configuration from '$cfpath'" 1>&2
readonly outpath=static/keyfish-config.json

mkdir -p static
cp -f -- "$cfpath" "$outpath"
cat >static.go <<EOF
// Code generated by $(basename $0). DO NOT EDIT.

package config

import "embed"

// A default static configuration is embedded.
//go:embed ${outpath}
var _cfg embed.FS

func init() {
	static = _cfg
	defaultPath = "$outpath"
}
EOF
