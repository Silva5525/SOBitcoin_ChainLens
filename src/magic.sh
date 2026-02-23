#!/usr/bin/env bash
set -euo pipefail

# Usage: ./concat_pro.sh [DIR]
DIR="${1:-.}"
DIR="${DIR%/}"  # strip trailing slash if any

OUT_NAME="ALL_FILES.txt"
OUT="$(pwd)/${OUT_NAME}"   # absolute path

# 1) Filenames to exclude (basename matches)
exclude_names=(
  ".gitignore"
  "Makefile"
  "Dockerfile"
  "Changelog.md"
  "pyproject.toml"
  "_init_.py"
  ".env.example"
  "uv.lock"
  "test.csv"
  "package-lock.json"
  "train.csv"
  "requirements.txt"
  "AGENTS.md"
  "${OUT_NAME}"
)

# 2) Extensions to exclude (case-insensitive, no leading dot)
exclude_exts=(
  "png"
  "pdf"
  "mp3"
  "ico"
  "zip"
  "md"
  "db"
)

# 3) Directories to exclude (any file under these is ignored)
exclude_dirs=(
  "node_modules"
  ".git"
  ".hg"
  ".svn"
  ".venv"
  "venv"
  "_pycache_"
  ".pytest_cache"
  ".mypy_cache"
  "dist"
  "build"
  ".next"
  ".turbo"
  ".idea"
)

# ---- build the find command safely ----
# We prune directories first to avoid walking into them at all.
find_cmd=( find "$DIR" )

for d in "${exclude_dirs[@]}"; do
  find_cmd+=( -path "/${d}/" -prune -o )
done

# Base predicate for remaining paths: regular files only
find_cmd+=( -type f )

# Exclude the output file itself (anti-recursion)
if [ -e "$OUT" ]; then
  find_cmd+=( ! -samefile "$OUT" )
fi

# Exclude specific basenames
for n in "${exclude_names[@]}"; do
  find_cmd+=( ! -name "$n" )
done

# Exclude extensions
for e in "${exclude_exts[@]}"; do
  find_cmd+=( ! -iname "*.${e}" )
done

# ---- run and build the file ----
: > "$OUT"

while IFS= read -r -d '' f; do
  rel="${f#"$DIR"/}"  # header path relative to DIR
  printf "\n\n# =================== %s\n\n" "${rel:-$f}" >> "$OUT"
  cat -- "$f" >> "$OUT"
done < <("${find_cmd[@]}" -print0)