#!/bin/sh
set -eu

# $1 is path to generated initramfs in boot-deploy working directory
bootimgfile="$(dirname "$1")/boot.img"
avbtool add_hash_footer \
	--image "$bootimgfile" \
	--partition_name boot \
	--partition_size 67108864 \
	--algorithm NONE
