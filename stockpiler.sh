#!/bin/bash
# Stockpiler — CVE PoC collector built on nomi-sec/PoC-in-GitHub
#
# Usage:
#   ./stockpiler.sh update             Sync index + clone any missing PoC repos (idempotent)
#   ./stockpiler.sh stat               Print collection / disk stats
#   ./stockpiler.sh search <query>     Search local repos.txt for a CVE or string

set -euo pipefail

PIGREPO="PoC-in-GitHub"
PIGURL="https://github.com/nomi-sec/PoC-in-GitHub"
CLONE_DELAY=5

# Never prompt for credentials — fail fast if a repo is private / auth required
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=true
export SSH_ASKPASS=true
export SSH_ASKPASS_REQUIRE=never

usage() {
    cat <<EOF
Stockpiler — CVE PoC collector (PoC-in-GitHub)

Usage: $(basename "$0") <command> [args]

Commands:
  update             Sync PoC-in-GitHub and clone any missing PoC repos (safe to re-run)
  stat               Show collection totals, per-year counts, and disk usage
  search <query>     Search local repos.txt for a CVE ID or string
EOF
    exit 1
}

# Clone a repo; only rate-limit (sleep) on success
git_clone() {
    local url="$1"
    local dest="$2"
    if git -c credential.helper= clone --quiet "$url" "$dest"; then
        sleep "$CLONE_DELAY"
        return 0
    else
        echo "Clone failed (skipped delay): $url" >&2
        return 1
    fi
}

ensure_pigrepo() {
    if [ ! -d "$PIGREPO/.git" ]; then
        echo "PoC-in-GitHub not found — cloning $PIGURL ..."
        rm -rf "$PIGREPO"
        git -c credential.helper= clone "$PIGURL" "$PIGREPO"
    else
        echo "Pulling $PIGREPO ..."
        pull_out=$(git -C "$PIGREPO" -c credential.helper= pull 2>&1) || true
        echo "$pull_out"
    fi
}

full_names_from_json() {
    jq -r '.[].full_name // empty' "$1"
}

# True if owner/repo is already cloned under this CVE directory
has_local_clone() {
    local cvedir="$1"
    local reponame="$2"
    local d
    for d in "$cvedir"/*/; do
        [ -d "$d$reponame" ] && return 0
    done
    return 1
}

next_slot() {
    local cvedir="$1"
    local d n
    d=$(find "$cvedir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
    n=$((d + 1))
    echo "$n"
}

cmd_update() {
    local -a new_clones=()
    local cloned=0
    local skipped=0
    local failed=0

    ensure_pigrepo
    echo "Syncing local collection from $PIGREPO ..."

    for year_dir in "$PIGREPO"/*/; do
        [ -d "$year_dir" ] || continue
        year=$(basename "$year_dir")
        mkdir -p "CVE-$year"

        for json in "$PIGREPO/$year"/*.json; do
            [ -f "$json" ] || continue
            cveid=$(basename "$json" .json)
            cvedir="CVE-$year/$cveid"
            repos_txt="$cvedir/repos.txt"
            mkdir -p "$cvedir"
            touch "$repos_txt"

            while IFS= read -r fn; do
                [ -n "$fn" ] || continue
                gitrepo="https://github.com/$fn"
                reponame=$(basename "$fn")

                # Keep repos.txt in sync (append-only; no duplicates)
                if ! grep -qFx "$gitrepo" "$repos_txt" 2>/dev/null; then
                    echo "$gitrepo" >> "$repos_txt"
                fi

                if has_local_clone "$cvedir" "$reponame"; then
                    skipped=$((skipped + 1))
                    continue
                fi

                n=$(next_slot "$cvedir")
                dest="$cvedir/$n/$reponame"
                echo "Cloning $gitrepo -> $dest"
                if git_clone "$gitrepo" "$dest"; then
                    cloned=$((cloned + 1))
                    new_clones+=("$cvedir")
                else
                    failed=$((failed + 1))
                    # Leave no empty numbered dir behind
                    rmdir "$cvedir/$n" 2>/dev/null || true
                fi
            done < <(full_names_from_json "$json")
        done
    done

    echo "Update finished."
    echo "Cloned: $cloned  Already present: $skipped  Failed: $failed"
    if [ ${#new_clones[@]} -gt 0 ]; then
        echo "CVEs with new clones:"
        printf '%s\n' "${new_clones[@]}" | sort -u
    fi
    print_totals
}

print_totals() {
    echo "Current collection total:"
    cvetotal=$(find . -maxdepth 1 -type d -name 'CVE-*' 2>/dev/null | wc -l | tr -d ' ')
    poctotal=0
    if compgen -G 'CVE-*/*/repos.txt' > /dev/null; then
        poctotal=$(cat CVE-*/*/repos.txt 2>/dev/null | wc -l | tr -d ' ')
    fi
    echo "CVEs: $cvetotal"
    echo "Proof-of-Concepts: $poctotal"
}

cmd_stat() {
    print_totals
    for cve in $(ls -d CVE-* 2>/dev/null | sort); do
        cveid=$(find "$cve" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')
        year=$(echo "$cve" | cut -d '-' -f2)
        echo "$year - $cveid"
    done
    echo "Calculating disk usage..."
    if command -v dust >/dev/null 2>&1; then
        dust -n 23 CVE-*
    else
        du -sh CVE-* 2>/dev/null | sort -h | tail -n 23
        echo "(install 'dust' for hierarchical disk usage)"
    fi
    echo "Complete."
}

cmd_search() {
    local q="${1:-}"
    if [ -z "$q" ]; then
        echo "Usage: $(basename "$0") search <query>" >&2
        exit 1
    fi
    local pocresults
    pocresults=$(grep -H -i -- "$q" CVE-????/CVE-????-*/repos.txt 2>/dev/null || true)
    if [ -z "$pocresults" ]; then
        echo "No matches for: $q"
        return 0
    fi
    local cveresults
    cveresults=$(echo "$pocresults" | cut -d '/' -f2 | sort -u)
    for i in $cveresults; do
        echo -e "\033[1;32mFound related CVE: \033[1;31m$i"
        echo -en "\033[00m"
        echo -e "\033[1;34mPoC-In-GitHub:"
        echo -en "\033[00m"
        cat CVE-????/"$i"/repos.txt 2>/dev/null || true
        echo -e "\033[1;35mFound local copy:"
        echo -en "\033[00m"
        for j in CVE-????/"$i"/*/*; do
            [ -e "$j" ] || continue
            echo "$j"
        done
    done
}

main() {
    local cmd="${1:-}"
    shift || true
    case "$cmd" in
        update|up|stage|stager|install) cmd_update "$@" ;;
        stat|stats)                     cmd_stat "$@" ;;
        search|s)                       cmd_search "$@" ;;
        -h|--help|help|"")              usage ;;
        *)
            echo "Unknown command: $cmd" >&2
            usage
            ;;
    esac
}

main "$@"
