#!/bin/sh
#
# Update the precompiled code for CryptoJS.
# Usage: update.sh [<version>]
# Output replaces the existing crypto-js.min.js.
#

# Verify that we have the tools we need.
check() { which "$1" >/dev/null || { echo "Missing $1" 1>&2; exit 1; } }
check browserify
check curl
check jq
check uglifyjs

# If a version is not specified, fetch the latest tagged version.
version="$1"
if [ "$version" = "" ] ; then
    version=$(
      curl --silent https://api.github.com/repos/brix/crypto-js/tags | \
      jq -r '[.[] | select(.name|match("^\\d"))][0].name' \
    )
    echo "Latest crypto-js tag: $version"
fi

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
echo ">> Fetching ${url}" 1>&2
curl -L -O "$url"
unzip -q "$(basename $url)"

echo ">> Bundling ${rootdir}" 1>&2
browserify --bare -s CryptoJS "$rootdir/crypto-js.js" \
    | uglifyjs --mangle --compress hoist_funs=1,passes=3 > crypto-js.min.js
cp -f -- crypto-js.min.js "$old"

echo "--- update complete" 1>&2
cd "$old"
if git diff --stat --exit-code crypto-js.min.js ; then
    echo "NO CHANGE" 1>&2
fi
