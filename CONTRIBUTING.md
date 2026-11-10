# Contributing

Contributions are welcome. **Security problems do not go here**: see [SECURITY.md](SECURITY.md).

## Before you start

- For anything larger than a fix, open an issue first and say what you want to change and why.
- By contributing you agree that your contribution is licensed under the licence in [LICENSE](LICENSE).
  There is no separate contributor agreement.
- Be decent: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Set up and run the checks

From a clone, Python 3.10 or later:

    python -m venv .venv
    # Windows PowerShell: .\.venv\Scripts\Activate.ps1   Linux/macOS: . .venv/bin/activate
    python -m pip install -e . pytest
    python -m pytest -q
    python spec/tools/make_vectors.py --check
    python scripts/check_install_lines.py
    sf-smartagency demo

## Rules a change must keep

1. No secrets, keys, endpoints or personal data in the repository. Issuer keys are PEM files and are
   ignored by `.gitignore`; never commit one, even for a test (tests use fixed seeds).
2. No new runtime dependency without a reason in the pull request. Today there are three: sf-smartfabric,
   cryptography and jsonschema.
3. A change to the contract format, the ledger rules or the monitor's decisions changes the vectors. Run
   `python spec/tools/make_vectors.py` (it also updates the copy in `src/sf_smartagency/data/`), review the
   diff of `spec/conformance/`, and update `spec/SPEC.md`. The vectors are the contract.
4. Fail closed: when the monitor cannot be sure (a ledger it cannot verify, an input it cannot parse), it
   denies.
5. Say what was tested and what was not. Do not write that something works on a platform or at a scale
   it was not run on. No performance figure without a measurement.
6. Install lines name only packages listed with `"registered": true` in `names.json`;
   `scripts/check_install_lines.py` enforces it in CI.
7. Add a line to [CHANGELOG.md](CHANGELOG.md) under "Unreleased".

## Pull requests

One topic per pull request. Describe what changes for a user, which tests cover it, and the commands
you ran with their results.
