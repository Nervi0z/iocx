# Contributing

Open an issue before starting any substantial change.

## Adding a new source

1. Add a function in `src/iocx/sources.py` — return a dict with `source` key, never raise.
2. Wire it into the relevant command in `src/iocx/cli.py` via `_parallel()`.
3. Add rendering logic in `src/iocx/output.py`.
4. Add tests in `tests/test_iocx.py` using `unittest.mock.patch`.

## Code style

```bash
black src/ tests/
flake8 src/ tests/
pytest
```

## Commit messages

Imperative mood, no period, 72 chars max.

```
Add Shodan domain lookup
Fix AbuseIPDB timeout handling
Update README with scan examples
```
