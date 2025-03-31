#!/bin/bash

test_file_create_only() {
  echo "=== test_file_create_only ==="
  touch "$ROOT/$tfile" || error "touch failed"
}

test_file_create_and_stat() {
  echo "=== test_file_create_and_stat ==="
  touch "$ROOT/$tfile" || error "touch failed"
  stat "$ROOT/$tfile" || error "stat failed"
}

test_file_write_and_grep() {
  echo "=== test_file_write_and_grep ==="
  echo "foo" > "$ROOT/$tfile" || error "failed to write 'foo'"
  grep "foo" "$ROOT/$tfile" || error "did not find 'foo'"
}

test_file_append() {
  echo "=== test_file_append ==="
  echo "foo" > "$ROOT/$tfile" || error "failed to write 'foo'"
  echo "bar" >> "$ROOT/$tfile" || error "failed to append 'bar'"
  grep "foo" "$ROOT/$tfile" || error "did not find 'foo'"
  grep "bar" "$ROOT/$tfile" || error "did not find 'bar'"
}

test_file_missing() {
  echo "=== test_file_missing ==="
  if stat "$ROOT/no_such_file"; then
    error "stat succeeded on missing file"
  fi
  echo "OK"
}

test_directory_create_and_list() {
  echo "=== test_directory_create_and_list ==="
  local dirname="$ROOT/testdir"
  mkdir "$dirname" || error "failed to mkdir"
  ls -ld "$dirname" || error "failed to ls directory"
  echo "OK"
}

test_directory_create_content_and_list() {
  echo "=== test_directory_create_content_and_list ==="
  local dirname="$ROOT/testdir_content"
  mkdir "$dirname" || error "failed to mkdir"
  echo "foo" > "$dirname/file1" || error "failed to create file1"
  echo "bar" > "$dirname/file2" || error "failed to create file2"
  ls -l "$dirname" | grep "file1" || error "did not find file1"
  ls -l "$dirname" | grep "file2" || error "did not find file2"
  echo "OK"
}

test_safetensors_create() {
  tmpfile=$(mktemp)
  chmod 777 $tmpfile
  cat << EOF > "$tmpfile"
import numpy as np
from safetensors.numpy import save_file
import os
import sys


rng = np.random.default_rng(42)

tensors = {
    "tensor1": rng.integers(0, 10000, size=(1024*4, 1024*4), dtype=np.int32),
    "tensor2": rng.integers(0, 100, size=(1024, 1024), dtype=np.int32),
    "tensor3": rng.integers(-1000, 1000, size=(1024*8), dtype=np.int64),
}

metadata = {
    "description": "This is tensor data for testing SafeTensors.",
    "created_by": "A" * 1866,
    "modified_by": "A" * 1866,
    "version": "1.0"
}

output_path = sys.argv[1]

save_file(tensors, output_path, metadata=metadata)
EOF
  mkdir $ROOT/$tfile
  /home/skoyama/miniconda3/bin/python3 $tmpfile $ROOT/$tfile/1.safetensors
  sleep 1
  /home/skoyama/miniconda3/bin/python3 $tmpfile $ROOT/$tfile/2.safetensors
  sleep 1
  ls -l $ROOT/$tfile
  sleep 5
  rm $tmpfile
}