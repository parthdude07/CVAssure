"""Tests for cvassure.provenance.merkle — RFC 6962-style Merkle tree."""

from __future__ import annotations

import pytest

from cvassure.provenance.merkle import EMPTY_ROOT, MerkleTree


def test_empty_tree_root(tmp_path=None):
    tree = MerkleTree()
    assert tree.root() == EMPTY_ROOT


def test_single_leaf(tmp_path=None):
    tree = MerkleTree()
    leaf = "a" * 64
    tree.add_leaf(leaf)
    root = tree.root()
    assert isinstance(root, str) and len(root) == 64
    assert root != EMPTY_ROOT


def test_two_leaves_deterministic(tmp_path=None):
    t1 = MerkleTree()
    t2 = MerkleTree()
    for h in ("a" * 64, "b" * 64):
        t1.add_leaf(h)
        t2.add_leaf(h)
    assert t1.root() == t2.root()


def test_different_leaves_different_root(tmp_path=None):
    t1 = MerkleTree()
    t2 = MerkleTree()
    t1.add_leaf("a" * 64)
    t2.add_leaf("b" * 64)
    assert t1.root() != t2.root()


def test_len(tmp_path=None):
    tree = MerkleTree()
    assert len(tree) == 0
    tree.add_leaf("a" * 64)
    assert len(tree) == 1
    tree.add_leaf("b" * 64)
    assert len(tree) == 2


def test_audit_proof_round_trip_even_count(tmp_path=None):
    """Verify proof for each leaf in a 4-leaf tree."""
    tree = MerkleTree()
    leaves = [chr(ord("a") + i) * 64 for i in range(4)]
    for leaf in leaves:
        tree.add_leaf(leaf)
    root = tree.root()
    for i, leaf in enumerate(leaves):
        proof = tree.proof(i)
        assert MerkleTree.verify_proof(leaf, proof, root) is True


def test_audit_proof_round_trip_odd_count(tmp_path=None):
    """Verify proof for each leaf in a 5-leaf tree (odd, last leaf duplicated)."""
    tree = MerkleTree()
    leaves = [chr(ord("a") + i) * 64 for i in range(5)]
    for leaf in leaves:
        tree.add_leaf(leaf)
    root = tree.root()
    for i, leaf in enumerate(leaves):
        proof = tree.proof(i)
        assert MerkleTree.verify_proof(leaf, proof, root) is True


def test_audit_proof_tampered_leaf_fails(tmp_path=None):
    tree = MerkleTree()
    leaves = ["a" * 64, "b" * 64, "c" * 64]
    for leaf in leaves:
        tree.add_leaf(leaf)
    root = tree.root()
    proof = tree.proof(0)
    # Wrong leaf
    assert MerkleTree.verify_proof("z" * 64, proof, root) is False


def test_audit_proof_wrong_root_fails(tmp_path=None):
    tree = MerkleTree()
    tree.add_leaf("a" * 64)
    tree.add_leaf("b" * 64)
    tree.root()
    proof = tree.proof(0)
    assert MerkleTree.verify_proof("a" * 64, proof, "c" * 64) is False


def test_proof_index_out_of_range():
    tree = MerkleTree()
    tree.add_leaf("a" * 64)
    with pytest.raises(IndexError):
        tree.proof(1)


def test_proof_empty_tree():
    tree = MerkleTree()
    with pytest.raises(IndexError):
        tree.proof(0)


def test_to_dict_keys(tmp_path=None):
    tree = MerkleTree()
    tree.add_leaf("a" * 64)
    d = tree.to_dict()
    assert "leaf_count" in d
    assert "root" in d
    assert "algorithm" in d
    assert d["leaf_count"] == 1


def test_root_changes_after_add(tmp_path=None):
    tree = MerkleTree()
    tree.add_leaf("a" * 64)
    root1 = tree.root()
    tree.add_leaf("b" * 64)
    root2 = tree.root()
    assert root1 != root2
