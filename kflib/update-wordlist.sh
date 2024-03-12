#!/usr/bin/env bash
#
# Usage: update-wordlist.sh <output-path>
#
# Fetch the EFF "long word list" for dice-generated passwords.
#
# This is meant to be run via "go generate".
set -euo pipefail
output="${1:?missing output path}"

readonly url='https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt'
curl -s -L "$url" | cut -f2 | sort > "$output"
