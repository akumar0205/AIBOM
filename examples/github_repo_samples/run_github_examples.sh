#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="${ROOT_DIR}/.tmp/github-repo-samples"
RESULTS_DIR="${ROOT_DIR}/examples/github_repo_samples/results/github"
SUMMARY_FILE="${RESULTS_DIR}/SUMMARY.md"

repos=(
  "openai/openai-quickstart-python"
  "anthropics/anthropic-sdk-python"
  "jxnl/instructor"
  "openai/openai-python"
)

mkdir -p "${WORK_DIR}" "${RESULTS_DIR}"

{
  echo "# GitHub scan summary"
  echo
  echo "| Repository | URL | Status | Output |"
  echo "|---|---|---|---|"
} > "${SUMMARY_FILE}"

for repo in "${repos[@]}"; do
  slug="${repo//\//-}"
  repo_url="https://github.com/${repo}"
  repo_dir="${WORK_DIR}/${slug}"
  out_dir="${RESULTS_DIR}/${slug}"
  log_file="${out_dir}/run.log"
  mkdir -p "${out_dir}"

  echo "==> Processing ${repo}"

  status="failed"
  output_path="n/a"

  if [[ ! -d "${repo_dir}/.git" ]]; then
    if ! git clone --depth 1 "${repo_url}.git" "${repo_dir}" > "${log_file}" 2>&1; then
      echo "| ${repo} | ${repo_url} | clone failed | ${log_file#${ROOT_DIR}/} |" >> "${SUMMARY_FILE}"
      continue
    fi
  else
    if ! {
      git -C "${repo_dir}" fetch --depth 1 origin &&
      git -C "${repo_dir}" reset --hard origin/HEAD
    } > "${log_file}" 2>&1; then
      echo "| ${repo} | ${repo_url} | refresh failed | ${log_file#${ROOT_DIR}/} |" >> "${SUMMARY_FILE}"
      continue
    fi
  fi

  if python -m aibom.cli generate "${repo_dir}" -o "${out_dir}/AI_BOM.json" >> "${log_file}" 2>&1 && \
     python -m aibom.cli validate "${out_dir}/AI_BOM.json" >> "${log_file}" 2>&1; then
    status="ok"
    output_path="${out_dir#${ROOT_DIR}/}/AI_BOM.json"
  else
    status="scan failed"
    output_path="${log_file#${ROOT_DIR}/}"
  fi

  echo "| ${repo} | ${repo_url} | ${status} | ${output_path} |" >> "${SUMMARY_FILE}"
  echo "   Status: ${status}"
done

echo "Done. Results in ${RESULTS_DIR}"
echo "Summary: ${SUMMARY_FILE}"
