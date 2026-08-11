#!/bin/sh
# shellcheck shell=sh

# Shared, sourceable CRS checkout verifier.  Callers set
# CRS_PROVENANCE_CONTEXT for a stable fail-closed diagnostic prefix.

CRS_EMPTY_GITMODULES_BLOB="e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"

crs_provenance_blocked() {
    ci_blocked "${CRS_PROVENANCE_CONTEXT:-crs_provenance} $*"
    return 1
}

crs_git() (
    unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR
    unset GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_EXEC_PATH
    unset GIT_TEMPLATE_DIR GIT_PROXY_COMMAND GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL
    unset GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS
    unset GIT_SSL_NO_VERIFY GIT_SSL_CAINFO GIT_SSL_CAPATH GIT_ASKPASS SSH_ASKPASS
    unset GIT_SSH GIT_SSH_COMMAND
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_COUNT=0 \
    GIT_TERMINAL_PROMPT=0 \
        git -c core.hooksPath=/dev/null -c protocol.file.allow=never \
            -c fetch.recurseSubmodules=false -c submodule.recurse=false \
            -c http.sslVerify=true "$@"
    return $?
)

crs_verify_checked_out_submodule_state() {
    tab=$(printf '\t')
    gitmodules_path="$CRS_SOURCE_DIR/.gitmodules"
    expected_tree_entry="100644 blob $CRS_EMPTY_GITMODULES_BLOB${tab}.gitmodules"
    expected_index_entry="100644 $CRS_EMPTY_GITMODULES_BLOB 0${tab}.gitmodules"
    gitmodules_tree_count=0

    if ! tree_entries=$(crs_git -C "$CRS_SOURCE_DIR" ls-tree -r "$CRS_APPROVED_COMMIT" 2>/dev/null); then
        crs_provenance_blocked "could not inspect the approved CRS tree"
        return 1
    fi
    while IFS= read -r tree_entry || [ -n "$tree_entry" ]; do
        case "$tree_entry" in
            160000\ commit\ *)
                crs_provenance_blocked "approved CRS tree contains a Gitlink"
                return 1
                ;;
            *"$tab".gitmodules)
                if [ "$tree_entry" != "$expected_tree_entry" ]; then
                    crs_provenance_blocked "approved CRS tree has a non-empty or non-regular .gitmodules entry"
                    return 1
                fi
                gitmodules_tree_count=$((gitmodules_tree_count + 1))
                ;;
            *"$tab"*/.gitmodules)
                crs_provenance_blocked "approved CRS tree contains a nested .gitmodules entry"
                return 1
                ;;
            *)
                :
                ;;
        esac
    done <<EOF
$tree_entries
EOF

    if [ "$gitmodules_tree_count" -gt 1 ]; then
        crs_provenance_blocked "approved CRS tree contains multiple .gitmodules entries"
        return 1
    fi

    if ! index_entries=$(crs_git -C "$CRS_SOURCE_DIR" ls-files --stage 2>/dev/null); then
        crs_provenance_blocked "could not inspect the checked-out CRS index"
        return 1
    fi
    while IFS= read -r index_entry || [ -n "$index_entry" ]; do
        case "$index_entry" in
            160000\ *)
                crs_provenance_blocked "checked-out CRS index contains a Gitlink"
                return 1
                ;;
            *)
                :
                ;;
        esac
    done <<EOF
$index_entries
EOF

    if crs_git -C "$CRS_SOURCE_DIR" config --local --get-regexp '^submodule\.' >/dev/null 2>&1; then
        crs_provenance_blocked "checked-out CRS config declares submodules"
        return 1
    else
        config_status=$?
        if [ "$config_status" -ne 1 ]; then
            crs_provenance_blocked "could not inspect checked-out CRS submodule configuration"
            return 1
        fi
    fi
    if [ -e "$CRS_SOURCE_DIR/.git/modules" ] || [ -L "$CRS_SOURCE_DIR/.git/modules" ]; then
        crs_provenance_blocked "checked-out CRS repository has a submodule registry"
        return 1
    fi

    if ! gitmodules_index_entry=$(crs_git -C "$CRS_SOURCE_DIR" ls-files --stage -- .gitmodules 2>/dev/null); then
        crs_provenance_blocked "could not inspect the checked-out .gitmodules index entry"
        return 1
    fi

    if [ "$gitmodules_tree_count" -eq 0 ]; then
        if [ -n "$gitmodules_index_entry" ] || [ -e "$gitmodules_path" ] || [ -L "$gitmodules_path" ]; then
            crs_provenance_blocked "checked-out CRS tree has an untracked .gitmodules path"
            return 1
        fi
        return 0
    fi

    if [ -L "$gitmodules_path" ] || [ ! -f "$gitmodules_path" ] || [ -s "$gitmodules_path" ]; then
        crs_provenance_blocked "checked-out .gitmodules is not an empty regular file"
        return 1
    fi
    if [ "$gitmodules_index_entry" != "$expected_index_entry" ]; then
        crs_provenance_blocked "checked-out .gitmodules index entry is not the approved empty blob"
        return 1
    fi
    if ! gitmodules_blob=$(crs_git -C "$CRS_SOURCE_DIR" rev-parse --verify "$CRS_APPROVED_COMMIT:.gitmodules" 2>/dev/null); then
        crs_provenance_blocked "could not resolve the approved .gitmodules blob"
        return 1
    fi
    if [ "$gitmodules_blob" != "$CRS_EMPTY_GITMODULES_BLOB" ]; then
        crs_provenance_blocked "approved .gitmodules blob is not the exact empty blob"
        return 1
    fi
    if ! gitmodules_size=$(crs_git -C "$CRS_SOURCE_DIR" cat-file -s "$CRS_APPROVED_COMMIT:.gitmodules" 2>/dev/null); then
        crs_provenance_blocked "could not measure the approved .gitmodules blob"
        return 1
    fi
    if [ "$gitmodules_size" != "0" ]; then
        crs_provenance_blocked "approved .gitmodules blob is not empty"
        return 1
    fi
    if ! gitmodules_hash=$(crs_git -C "$CRS_SOURCE_DIR" hash-object --no-filters -- "$gitmodules_path" 2>/dev/null); then
        crs_provenance_blocked "could not hash the checked-out .gitmodules file"
        return 1
    fi
    if [ "$gitmodules_hash" != "$CRS_EMPTY_GITMODULES_BLOB" ]; then
        crs_provenance_blocked "checked-out .gitmodules content is not the approved empty blob"
        return 1
    fi
    if ! crs_git -C "$CRS_SOURCE_DIR" -c core.fileMode=true diff --quiet --no-ext-diff --no-textconv -- .gitmodules; then
        crs_provenance_blocked "checked-out .gitmodules differs from the approved index"
        return 1
    fi
}

crs_verify_checked_out_provenance() {
    if ! checked_out_commit=$(crs_git -C "$CRS_SOURCE_DIR" rev-parse --verify "HEAD^{commit}" 2>/dev/null); then
        crs_provenance_blocked "could not resolve the checked-out CRS commit"
        return 1
    fi
    if [ "$checked_out_commit" != "$CRS_APPROVED_COMMIT" ]; then
        crs_provenance_blocked "checked-out CRS commit does not match the approved commit"
        return 1
    fi
    if ! remote_url=$(crs_git -C "$CRS_SOURCE_DIR" config --get remote.origin.url 2>/dev/null); then
        crs_provenance_blocked "could not inspect the checked-out CRS origin"
        return 1
    fi
    if [ "$remote_url" != "$CRS_APPROVED_REPO_URL" ]; then
        crs_provenance_blocked "CRS checkout has unexpected origin: $remote_url"
        return 1
    fi
    if ! checked_out_tag_commit=$(crs_git -C "$CRS_SOURCE_DIR" rev-parse --verify "refs/tags/$CRS_RELEASE_TAG^{}" 2>/dev/null); then
        crs_provenance_blocked "could not resolve the reviewed CRS release tag"
        return 1
    fi
    if [ "$checked_out_tag_commit" != "$CRS_APPROVED_COMMIT" ]; then
        crs_provenance_blocked "reviewed CRS release tag does not peel to the approved commit"
        return 1
    fi
    if ! crs_verify_checked_out_submodule_state; then
        return 1
    fi
    if ! crs_git -C "$CRS_SOURCE_DIR" diff --quiet --no-ext-diff --no-textconv; then
        crs_provenance_blocked "checked-out CRS worktree differs from the approved index"
        return 1
    fi
    if ! crs_git -C "$CRS_SOURCE_DIR" diff --cached --quiet --no-ext-diff --no-textconv; then
        crs_provenance_blocked "checked-out CRS index differs from the approved commit"
        return 1
    fi
    if ! untracked_entries=$(crs_git -C "$CRS_SOURCE_DIR" ls-files --others --no-empty-directory 2>/dev/null); then
        crs_provenance_blocked "could not inspect untracked CRS files"
        return 1
    fi
    if [ -n "$untracked_entries" ]; then
        crs_provenance_blocked "checked-out CRS worktree contains untracked files"
        return 1
    fi
}
