import filecmp
import os
import subprocess
import sys

from sf_smartagency import __version__
from sf_smartagency._bundled import path
from sf_smartagency.conformance import FILES, run_dir

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, "spec", "conformance")


def test_all_vectors_pass():
    total, fails = run_dir(SPEC)
    assert fails == []
    assert total == 162


def test_bundled_copies_equal_spec():
    for f in FILES:
        assert filecmp.cmp(os.path.join(SPEC, f), path("conformance", f), shallow=False), f
    assert filecmp.cmp(os.path.join(ROOT, "spec", "schema", "contract.schema.json"),
                       path("schema", "contract.schema.json"), shallow=False)


def test_generator_is_in_sync():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "spec", "tools", "make_vectors.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_versions_agree():
    import json
    assert f'version = "{__version__}"' in open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert json.load(open(os.path.join(ROOT, ".smart.json")))["version"] == __version__
