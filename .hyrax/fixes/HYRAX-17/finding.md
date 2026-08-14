# No lockfile — non-reproducible builds and silent dependency drift

**Tool:** `deps`
**Severity:** high
**Category:** operations
**Location:** `requirements.txt:0`

## What's wrong

The project ships only `requirements.txt` with loose version ranges (e.g. `Flask>=3.1,<4`, `Pillow>=10,<13`) and has no lockfile (`pip.lock`, `poetry.lock`, `uv.lock`, or `requirements.txt --require-hashes`). Without a lockfile, every fresh install (`pip install -r requirements.txt` or `START_SERVER.bat`) resolves transitive dependencies independently, meaning two machines — or the same machine at different points in time — can install different versions of every package in the tree.

This has two concrete risks for this app:

1. **Silent breakage**: A new release of any transitive dependency can introduce incompatible behaviour or a bug between deployments, with no audit trail.
2. **Supply-chain exposure**: Without integrity hashes, a compromised mirror or a registry package replacement cannot be detected at install time. The `START_SERVER.bat` script runs `pip install -r requirements.txt` automatically on every launch, making this attack surface always-active.

## What changed

Generate a locked, hash-verified requirements file:

```
pip install pip-tools
pip-compile --generate-hashes requirements.txt -o requirements.lock
```

Then use `pip install --require-hashes -r requirements.lock` (or `pip-sync requirements.lock`) for installs. Update `START_SERVER.bat` to reference `requirements.lock`. Regenerate the lock file whenever `requirements.txt` changes.
