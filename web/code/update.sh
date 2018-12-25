#!/bin/sh
#
# Update the precompiled code for CryptoJS.
# Usage: update.sh [<version>]
# Output replaces the existing crypt-js.js.

# If a version is not specified, the latest known-good version is used.
# Update this script if you verify a newer version works.
readonly version="${1:-3.1.9-1}"

# Verify that we have the tools we need.
check() { which "$1" >/dev/null || { echo "Missing $1" 1>&2; exit 1; } }
check browserify
check uglifyjs

echo "--- Updating CryptoJS to ${version} ..." 1>&2
readonly url="https://github.com/brix/crypto-js/archive/${version}.zip"
readonly rootdir="crypto-js-${version}"

set -o pipefail
set -e

# Remember the location where the script is stored, so we can copy the file
# back there once it's been generated.
old="$(cd $(dirname $0) 1>/dev/null ; pwd)"

# Create a temp directory so we can fetch and unpack and munge the source.
tmp="$(mktemp -d)"
trap "rm -fr -- '$tmp'" EXIT
cd "$tmp" 1>/dev/null

# Fetch the specified version of CryptoJS and run webpack to collapse the
# requirements and minify the components we need here.
curl -L -O "$url"
unzip -q "$(basename $url)"
browserify --bare -s CryptoJS crypto-js-3.1.9-1/crypto-js.js \
    | uglifyjs --mangle --compress hoist_funs=1,passes=3 > crypto-js.min.js
cp -f -- crypto-js.min.js "$old"

cd "$old"
if git diff --stat --exit-code crypto-js.min.js ; then
    echo "NO CHANGE"
fi
