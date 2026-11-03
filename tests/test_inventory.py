from quantasentry.inventory import inventory


def test_finds_rsa_reference(tmp_path):
    (tmp_path/"crypto.py").write_text("key = RSA.generate(2048)\n")
    rows=inventory(tmp_path)
    assert rows and rows[0]["algorithm_reference"]=="RSA"
