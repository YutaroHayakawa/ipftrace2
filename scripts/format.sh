#!/bin/sh

# Run this script from top directory

check_diff() {
	for file in $(find ./src -mindepth 1 -maxdepth 1 -regex ".*\.[ch]"); do
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
	echo "Source format is up to date"
	exit 0
}

$1
