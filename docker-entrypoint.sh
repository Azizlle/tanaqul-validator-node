#!/bin/sh
# Tanaqul validator node — entrypoint.
#
# WHY THIS EXISTS. The image creates /data and chowns it to `validator` (uid 1000),
# but that ownership belongs to the IMAGE LAYER. The moment a volume is mounted at
# /data — which every real deployment must do, or the node loses its identity on every
# restart — the mount SHADOWS that directory and arrives owned by root. The unprivileged
# process then cannot create /data/validator_key.pem.tmp and the container crash-loops
# with PermissionError [Errno 13]. Measured on Railway, 2026-09-13.
#
# So ownership has to be fixed at RUNTIME, on every start, before privileges are
# dropped. The node itself never runs as root: this script does exactly one privileged
# thing and then hands over with exec, so the signing process is uid 1000 as before.
set -e

if [ "$(id -u)" = "0" ]; then
    # -R because a volume may already hold a root-owned key from an earlier attempt.
    chown -R validator:validator /data
    exec gosu validator "$@"
fi

# Already unprivileged (plain `docker run` with no volume, or a platform that pins the
# user). Nothing to fix and no way to fix it — run as we are and let a genuine
# permission problem fail loudly rather than be papered over.
exec "$@"
