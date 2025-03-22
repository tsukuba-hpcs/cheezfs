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
