#!/bin/bash

source setup.sh
source sanity.sh

error() {
  echo "[ERROR] $1"
  exit 1
}

export ROOT="$PWD/mnt"
export ORIGIN="/mnt/btrfs"
setup

tests=($(declare -F | awk '{print $3}' | grep '^test_'))

for i in "${!tests[@]}"; do
  test_name="${tests[$i]}"
  tfile="test_${i}.tmp"
  export tfile

  echo "Running $test_name..."
  $test_name
  if [ $? -eq 0 ]; then
    echo "[PASS] $test_name"
  else
    echo "[FAIL] $test_name"
  fi
done

echo "All tests finished."

cleanup