from pathlib import Path

from quantasentry.inventory import inventory


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
    original=Path.rglob
    def reversed_rglob(self,pattern):
        return list(reversed(list(original(self,pattern))))
    monkeypatch.setattr(Path,"rglob",reversed_rglob)
    paths=[row["path"] for row in inventory(tmp_path)]
    assert paths==sorted(paths)
