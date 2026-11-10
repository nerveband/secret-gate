#!/bin/sh
# Free disk after a deploy. Run it once the new container reports healthy.
#
#   deploy/cleanup.sh [image-name] [rollback-tags-to-keep]
#
# Every build leaves about 1 GB behind: the Go build stage of the Dockerfile.
# A build that failed or was cancelled also leaves an exited build container,
# and that container pins its stage so a plain `docker image prune` cannot
# remove it. This script removes those containers, then untagged images,
# then rollback tags (image:vX.Y.Z) older than the newest N (default 3).
# Running containers and their images are never touched.
#
# DRY_RUN=1 prints what would be removed.
set -eu

image=${1:-secret-gate}
keep=${2:-3}

run() {
	if [ -n "${DRY_RUN:-}" ]; then
		echo "would run: $*"
	else
		"$@" >/dev/null
	fi
}

# Exited build containers (their command is the Dockerfile's go build step).
docker ps -a --no-trunc --filter status=exited --format '{{.ID}} {{.Command}}' |
	awk '/CGO_ENABLED/ { print $1 }' |
	while read -r id; do
		run docker rm "$id"
	done

# Untagged images, now that nothing pins the build stages.
run docker image prune -f

# Rollback tags older than the newest $keep.
docker images "$image" --format '{{.Tag}}' |
	grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' |
	sort -t. -k1.2,1nr -k2,2nr -k3,3nr |
	awk -v keep="$keep" 'NR > keep' |
	while read -r tag; do
		run docker rmi "$image:$tag"
	done

docker system df
