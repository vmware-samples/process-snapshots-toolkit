#!/bin/bash

set -e

# files/directories to test
FILES="process_snapshot_toolkit process_snapshot_toolkit_test ghidra_scripts scripts"

# Print usage if no arguments passed
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 [--inline|OUTPUT_FILE]"
    exit 1
fi

# Run black according to arguments passed.
if [ $1 = '--inline' ]; then
    black $FILES
else
    # If black encounters changes that need to be made, it will exit with status=1
    black --check --diff $FILES &> "$1"
fi

exit 0
