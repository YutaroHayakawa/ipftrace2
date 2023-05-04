#!/bin/sh

# Run this script from top directory

build() {
	cat README.tmpl.md | \
		CMDREF=$(./src/ipft -h 2>&1) \
		envsubst > README.md

	cat docs/bpf_extension.tmpl.md | \
		SKELETON=$(./src/ipft --gen bpf-module-skeleton 2>&1) \
		HEADER=$(./src/ipft --gen bpf-module-header 2>&1) \
		envsubst > docs/bpf_extension.md
}

check_diff() {
	for file in README.md docs/bpf_extension.md; do
		diff="$(git diff $file)"
		if [ $? != "0" ]; then
			echo "git diff failed"
			echo $diff
			exit 1
		fi
		if [ ! -z "$diff" ]; then
			echo "$file needs update"
			echo "$(git diff $file)"
			exit 1
		fi
	done
	echo "Documents are up to date"
	exit 0
}

$1
