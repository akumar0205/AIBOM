# GitHub Repository AIBOM Samples

This folder demonstrates what AIBOM output looks like and provides a repeatable workflow for scanning smaller, well-known AI Python repositories on GitHub.

## Included sample outputs in this repo

These JSON files are committed so reviewers can inspect schema shape and field density immediately:

- `results/aibom_repo.json` — AIBOM generated for this `AIBOM` project.
- `results/sample_project.json` — AIBOM generated for `tests/fixtures/sample_project`.

## Repositories scanned by the script

The scan script targets these GitHub repos and links directly to each one:

- [`openai/openai-quickstart-python`](https://github.com/openai/openai-quickstart-python)
- [`anthropics/anthropic-sdk-python`](https://github.com/anthropics/anthropic-sdk-python)
- [`jxnl/instructor`](https://github.com/jxnl/instructor)
- [`openai/openai-python`](https://github.com/openai/openai-python)

Run:

```bash
bash examples/github_repo_samples/run_github_examples.sh
```

The script writes outputs to `examples/github_repo_samples/results/github/` and creates:

- per-repo `AI_BOM.json` when scans succeed
- per-repo `run.log` for troubleshooting
- `results/github/SUMMARY.md` with repo URL + scan status + output path

## Expected output layout

After a successful run, you should see directories such as:

- `results/github/openai-openai-quickstart-python/AI_BOM.json`
- `results/github/anthropics-anthropic-sdk-python/AI_BOM.json`
- `results/github/jxnl-instructor/AI_BOM.json`
- `results/github/openai-openai-python/AI_BOM.json`
- `results/github/SUMMARY.md`

Validate any generated output with:

```bash
python -m aibom.cli validate <path-to-ai-bom.json>
```
