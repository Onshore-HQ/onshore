"""Exercises the Python SDK against the running end-to-end install."""
import json
import ssl
import sys

from onshore import VaultClient, VaultError

cfg = json.load(open(sys.argv[1]))
ctx = ssl._create_unverified_context()  # the test install uses a private CA
vault = VaultClient(cfg["base"], cfg["sa"], cfg["kid"], cfg["seed"], ssl_context=ctx)

items = [{"field": "bvn", "value": "22444455566"}, {"field": "phone", "value": "08031112222"}]
tokens = vault.tokenize(cfg["vault"], items)
assert all(t["token"].startswith("tok_") for t in tokens), tokens
assert vault.tokenize(cfg["vault"], items[:1])[0]["token"] == tokens[0]["token"]
assert vault.lookup(cfg["vault"], "bvn", "22444455566") == tokens[0]["token"]
found = vault.detect("Abeg check my BVN, na 22444455566", tokenize=True, vault=cfg["vault"])
assert "22444455566" not in found["text"] and tokens[0]["token"] in found["text"], found
try:
    vault.detokenize(cfg["vault"], [tokens[0]["token"]], "backend read")
    raise SystemExit("detokenize should be denied by default")
except VaultError as e:
    assert e.code == "policy_denied", e
print("Python SDK: tokenize, determinism, lookup, detect and default deny all ok")
