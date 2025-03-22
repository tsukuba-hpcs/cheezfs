#!/bin/bash

setup() {
    rm -rf "$ROOT"
    mkdir -p "$ROOT"
    fallocate -l 1G /tmp/disk.img
    export LOOP_DEV=$(sudo losetup --show -f /tmp/disk.img)
    mkfs.btrfs -f $LOOP_DEV
    mkdir -p $ORIGIN
    mount $LOOP_DEV $ORIGIN
    $PWD/build/sbin/cheezfs -d -f --source=$ORIGIN $ROOT &
}

cleanup() {
    fusermount -u "$ROOT"
    umount $ORIGIN
    losetup -d $LOOP_DEV
    rm -rf $ORIGIN
    rm -rf /tmp/disk.img
    rm -rf "$ROOT"
}