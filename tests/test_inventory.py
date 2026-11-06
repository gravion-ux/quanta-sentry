import importlib
import os

import quantasentry
from quantasentry.inventory import inventory

# The package exports the ``inventory`` function, which shadows the module of
# the same name. Resolve the module explicitly so the module-level helpers are
# reachable from the tests.
inventory_module = importlib.import_module("quantasentry.inventory")


def test_finds_rsa_reference(tmp_path):
    (tmp_path/"crypto.py").write_text("key = RSA.generate(2048)\n")
    rows=inventory(tmp_path)
    assert rows and rows[0]["algorithm_reference"]=="RSA"


def test_post_quantum_dsa_is_not_reported_as_legacy_dsa(tmp_path):
    (tmp_path/"pqc.py").write_text("sig = ML-DSA.sign(key)\n")
    algorithms={row["algorithm_reference"] for row in inventory(tmp_path)}
    assert algorithms=={"ML-DSA"}


def test_sphincs_dsa_is_not_reported_as_legacy_dsa(tmp_path):
    (tmp_path/"pqc.py").write_text("sig = SLH-DSA.sign(key)\n")
    algorithms={row["algorithm_reference"] for row in inventory(tmp_path)}
    assert algorithms=={"SLH-DSA"}


def test_legacy_dsa_is_still_reported(tmp_path):
    (tmp_path/"legacy.py").write_text("sig = DSA.sign(key)\n")
    algorithms={row["algorithm_reference"] for row in inventory(tmp_path)}
    assert algorithms=={"DSA"}


def test_dependency_directories_are_not_scanned(tmp_path):
    (tmp_path/".venv").mkdir()
    (tmp_path/".venv"/"dep.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n")
    (tmp_path/"node_modules").mkdir()
    (tmp_path/"node_modules"/"dep.js").write_text("const key = RSA.generate(2048);\n")
    (tmp_path/"app.py").write_text("value = 1\n")
    assert inventory(tmp_path)==[]


def test_inventory_order_does_not_depend_on_filesystem_order(tmp_path, monkeypatch):
    for name in ("zeta.py","Alpha.py","_under.py","beta.py"):
        (tmp_path/name).write_text("RSA\n")
    original = os.walk
    def reversed_walk(top, *args, **kwargs):
        for dirpath, dirnames, filenames in original(top, *args, **kwargs):
            yield dirpath, list(reversed(dirnames)), list(reversed(filenames))
    monkeypatch.setattr(inventory_module.os, "walk", reversed_walk)
    paths=[row["path"] for row in inventory(tmp_path)]
    assert paths==sorted(paths)


# --- file types in scope -----------------------------------------------------


def test_more_source_types_are_scanned(tmp_path):
    (tmp_path/"service.cs").write_text("var rsa = RSA.Create();\n")
    (tmp_path/"deploy.sh").write_text("openssl rsa -in key.pem\n")
    algorithms={row["algorithm_reference"] for row in inventory(tmp_path)}
    assert algorithms=={"RSA"}


def test_configuration_files_are_scanned(tmp_path):
    (tmp_path/"settings.yaml").write_text("algorithm: ECDSA\n")
    algorithms={row["algorithm_reference"] for row in inventory(tmp_path)}
    assert algorithms=={"ECDSA"}


def test_known_filenames_without_an_extension_are_scanned(tmp_path):
    (tmp_path/"Dockerfile").write_text("RUN openssl rsa -help\n")
    assert inventory(tmp_path)


def test_environment_files_are_not_scanned(tmp_path):
    (tmp_path/".env").write_text("PRIVATE_KEY=RSA_PRIVATE_KEY_MATERIAL\n")
    assert inventory(tmp_path)==[]


def test_private_key_files_are_not_scanned(tmp_path):
    (tmp_path/"server.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\n")
    assert inventory(tmp_path)==[]


def test_prose_files_are_not_scanned(tmp_path):
    (tmp_path/"README.md").write_text("We recommend RSA for compatibility.\n")
    assert inventory(tmp_path)==[]


# --- symbolic links ----------------------------------------------------------


class _FakeSymlink:
    """Minimal path-like object that reports itself as a symbolic link."""

    def __init__(self, parts):
        self._parts = tuple(parts)

    @property
    def parts(self):
        return self._parts

    def relative_to(self, other):
        return self

    def is_symlink(self):
        return True


def test_should_scan_rejects_a_symbolic_link():
    assert inventory_module.should_scan(_FakeSymlink(("project", "link.py")), "/project") is False


def test_should_scan_accepts_an_ordinary_source_file(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("value = 1\n")
    assert inventory_module.should_scan(path, tmp_path) is True


def test_symlinked_directory_is_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("key = RSA.generate(2048)\n")
    project = tmp_path / "project"
    project.mkdir()
    try:
        (project / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        import pytest
        pytest.skip("symbolic links require an extra privilege on this platform")
    assert inventory(project)==[]


# --- report ------------------------------------------------------------------


def test_report_summarises_the_scan(tmp_path):
    (tmp_path/"a.py").write_text("key = RSA.generate(2048)\n")
    (tmp_path/"b.py").write_text("sig = DSA.sign(key)\n")
    report = inventory_module.inventory_report(tmp_path)
    assert report["files_scanned"] == 2
    assert report["findings"] == 2
    assert report["by_algorithm"] == {"DSA": 1, "RSA": 1}
    assert len(report["inventory"]) == 2


def test_report_paths_are_relative_to_the_scanned_root(tmp_path):
    (tmp_path/"a.py").write_text("key = RSA.generate(2048)\n")
    report = inventory_module.inventory_report(tmp_path)
    assert report["inventory"][0]["path"] == "a.py"


# --- public API --------------------------------------------------------------


def test_package_exposes_the_public_api():
    assert quantasentry.inventory is inventory
    assert quantasentry.inventory_report is inventory_module.inventory_report
    assert quantasentry.__version__


def test_excluded_file_types_are_not_part_of_the_scope():
    assert ".env" not in quantasentry.EXTENSIONS
    assert ".pem" not in quantasentry.EXTENSIONS
