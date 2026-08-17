# requirements.txt uses unpinned version ranges with no lockfile — non-reproducible installs

**Tool:** `deps`
**Severity:** high
**Category:** operations
**Location:** `requirements.txt:1`

## What's wrong

`requirements.txt` pins only loose ranges (`Flask>=3.1,<4`, `Flask-WTF>=1.2,<2`, `Flask-Limiter>=4,<5`, `Waitress>=3.0,<4`, `Pillow>=10,<13`, `reportlab>=4.2,<5`) and there is no `requirements.lock`, `pip-compile` output, or `pyproject.toml`/`poetry.lock` anywhere in the repo. `START_SERVER.bat` runs `python -m pip install -r requirements.txt` directly against these ranges on every machine that lacks the packages already, so the exact resolved version set depends entirely on whatever is newest on PyPI at install time.

Because this project ships to end users as a self-hosted Windows service (via `START_SERVER.bat` / the scheduled-task installer scripts) rather than a controlled deployment pipeline, different installs on different machines/dates can silently resolve to different dependency versions — one install might get `Pillow` 10.x and another 12.x, with no record of which was actually tested. This is a bigger risk than in a typical CI-deployed web app because there is no build artifact or container image pinning the resolved set, and no CI to catch drift.

## What changed

Generate and commit a lockfile so every install resolves identically:
1. Adopt `pip-compile` (from `pip-tools`) or `uv pip compile` to produce a `requirements.lock.txt` with fully pinned versions (and ideally `--generate-hashes`).
2. Change `START_SERVER.bat` to install from the lockfile (`pip install -r requirements.lock.txt`) instead of the loose `requirements.txt`.
3. Keep `requirements.txt` as the human-edited source of ranges, regenerating the lock on every dependency bump.
