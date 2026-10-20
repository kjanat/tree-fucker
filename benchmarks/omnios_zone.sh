#!/bin/sh
# One-time setup inside the acceptance VM; no external network interface.
set -eu

if ! zfs list -H -o name rpool/zones >/dev/null 2>&1; then
	zfs create -o mountpoint=/zones rpool/zones
fi
if ! zonecfg -z tree-fucker-coordination info >/dev/null 2>&1; then
	zonecfg -z tree-fucker-coordination 'create -t lipkg; set zonepath=/zones/tree-fucker-coordination; set ip-type=shared; commit'
fi
zoneadm -z tree-fucker-coordination install
zoneadm -z tree-fucker-coordination boot
# zoneadm returns before SMF mounts /var/run. Wait for that parent tmpfs
# before creating the rendezvous so startup cannot hide the test directory.
attempt=0
until zlogin tree-fucker-coordination svcadm enable -s svc:/system/filesystem/minimal:default; do
	attempt=$((attempt + 1))
	if [ "${attempt}" -ge 60 ]; then
		echo "zone filesystem service did not become available" >&2
		exit 1
	fi
	sleep 1
done
zlogin tree-fucker-coordination mkdir -p /var/run/tree-fucker
zlogin tree-fucker-coordination chmod 1777 /var/run/tree-fucker
