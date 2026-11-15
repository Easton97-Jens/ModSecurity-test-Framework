#!/usr/bin/env bash
# Check only already available local objects; callers own fetching and identity.
set -eu

fail() {
    printf 'verify-mrts-update-lineage: %s\n' "$1" >&2
    exit 1
}

[[ $# -eq 3 ]] || fail 'expected REPOSITORY CURRENT_SHA CANDIDATE_SHA'
repository=$1
current=$2
candidate=$3
[[ $current =~ ^[0-9a-f]{40}$ ]] || fail 'current SHA must be a full lowercase SHA-1'
[[ $candidate =~ ^[0-9a-f]{40}$ ]] || fail 'candidate SHA must be a full lowercase SHA-1'

# Partial clones must not turn this read-only local check into a fetch.
export GIT_NO_LAZY_FETCH=1
for revision in "$current" "$candidate"; do
    object_type=$(git --no-replace-objects -C "$repository" cat-file -t "$revision" 2>/dev/null) ||
        fail 'required local object is unavailable or Git inspection failed'
    [[ $object_type == commit ]] || fail 'required local object is not a commit'
done

if git --no-replace-objects -C "$repository" merge-base --is-ancestor "$current" "$candidate" 2>/dev/null; then
    exit 0
else
    status=$?
    if [[ $status -eq 1 ]]; then
        fail 'candidate does not descend from current commit'
    fi
    fail 'Git ancestry inspection failed'
fi
