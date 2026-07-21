#!/usr/bin/env python3
# Copyright (c) 2024 The TensorCash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""VDF proof generation helper for TensorCash functional tests."""

import hashlib
import os
import struct
import subprocess
from io import BytesIO
from typing import Dict, Optional, Tuple
from test_framework.messages import CProofBlob

# Try to import chiavdf for real proof generation
try:
    import chiavdf
    HAS_CHIAVDF = True
except ImportError:
    HAS_CHIAVDF = False
    print("Warning: chiavdf not available. Using test vectors only.")


# Maintain a small cache of cumulative_tick values keyed by block hash (big-end hex).
# This allows helpers to derive the parent's cumulative tick when preparing a child block
# without querying a node.
_CUMULATIVE_TICK_CACHE: Dict[str, int] = {}


def cache_block_cumulative(block_hash_hex: str, cumulative_tick: int) -> None:
    """Record the cumulative_tick for a solved block so children can look it up."""
    if not block_hash_hex:
        return
    # Normalize to lowercase to avoid mismatched keys.
    _CUMULATIVE_TICK_CACHE[block_hash_hex.lower()] = int(cumulative_tick)

def refresh_cumulative_tick_cache_from_node(node, block_hash_hex: Optional[str] = None, depth: int = 10) -> None:
    """
    Refresh the cumulative_tick cache from the node's blockchain state.
    This is useful after node restarts to ensure cache consistency.

    Args:
        node: RPC connection to the node
        block_hash_hex: Starting block hash (defaults to best block)
        depth: How many blocks back to cache (default 10)
    """
    try:
        current_hash = block_hash_hex or node.getbestblockhash()

        for _ in range(depth):
            if current_hash == "0" * 64:  # Genesis
                break

            try:
                block_hex = node.getblock(current_hash, 0)
                # Parse block to get cumulative_tick
                from io import BytesIO
                from test_framework.messages import CBlock
                f = BytesIO(bytes.fromhex(block_hex))
                block = CBlock()
                block.deserialize(f)

                cumulative = int(getattr(block, 'cumulative_tick', 0))
                cache_block_cumulative(current_hash, cumulative)

                # Move to parent
                if hasattr(block, 'hashPrevBlock'):
                    current_hash = format(block.hashPrevBlock, '064x')
                else:
                    break
            except Exception:
                break
    except Exception:
        pass  # Best effort - don't fail if node is unavailable


def _lookup_parent_cumulative(parent_hash_hex: str) -> Optional[int]:
    """Return cached cumulative_tick for the given parent hash, if known."""
    if not parent_hash_hex:
        return None
    return _CUMULATIVE_TICK_CACHE.get(parent_hash_hex.lower())

# Known test vectors for when chiavdf is not available
TEST_VECTORS = {
    # (challenge_hex, tick, discr_bits): proof_hex
    ("0000000000000000000000000000000000000000000000000000000000000000", 1998848, 1024):
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100",
}

def generate_vdf_proof(challenge: bytes, iterations: int, discriminant_size_bits: int = 1024) -> bytes:
    """
    Generate a VDF proof for the given challenge and iterations.

    Args:
        challenge: 32-byte challenge (usually previous block hash)
        iterations: Number of VDF iterations (tick)
        discriminant_size_bits: Size of discriminant in bits (default 1024)

    Returns:
        VDF proof bytes
    """
    if len(challenge) != 32:
        raise ValueError(f"Challenge must be 32 bytes, got {len(challenge)}")

    # Check if we have a test vector for this
    challenge_hex = challenge.hex()
    vector_key = (challenge_hex, iterations, discriminant_size_bits)
    if vector_key in TEST_VECTORS:
        return bytes.fromhex(TEST_VECTORS[vector_key])

    helper = os.environ.get("TSC_VDF_TEST_HELPER")
    if helper:
        if discriminant_size_bits != 1024:
            raise ValueError("vdf_test_helper supports only the consensus 1024-bit profile")
        # uint256's display hex is the reverse of the raw 32 bytes carried in
        # the block header. The helper converts it back to the exact internal
        # byte span consumed by GenerateProofForTesting.
        proof_hex = subprocess.check_output(
            [helper, challenge[::-1].hex(), str(iterations)],
            text=True,
            timeout=120,
        ).strip()
        return bytes.fromhex(proof_hex)

    if HAS_CHIAVDF:
        # Generate real proof using chiavdf
        try:
            # Try the simpler prove_from_hash if available
            if hasattr(chiavdf, 'prove_from_hash'):
                # Use the simple API that matches C++ ProveSlow
                proof = chiavdf.prove_from_hash(
                    challenge,
                    discriminant_size_bits,
                    iterations
                )
                return proof
            else:
                # Fallback to the original prove API with correct arguments
                # The 5th argument is shutdown_file_path
                # The 2nd argument x_s is the serialized initial form

                # Create discriminant
                discriminant = chiavdf.create_discriminant(challenge, discriminant_size_bits)

                # Create initial form x = (2, 1, D) and serialize it
                # For the x_s parameter, we need to serialize the initial form
                # In the simple case, we can pass empty string and let it create the default
                x_s = ""  # Let the C++ code create the default form (2, 1, D)

                proof = chiavdf.prove(
                    challenge,
                    x_s,  # serialized initial form (empty = default)
                    discriminant_size_bits,
                    iterations,
                    ""  # shutdown_file_path (empty = no shutdown)
                )
                return proof

        except Exception as e:
            print(f"Failed to generate VDF proof with chiavdf: {e}")
            # Fall through to default

    # Default: Generate a plausible-looking proof for testing
    # This won't pass actual verification but allows tests to run
    return generate_fake_vdf_proof(challenge, iterations, discriminant_size_bits)

def generate_fake_vdf_proof(challenge: bytes, iterations: int, discriminant_size_bits: int) -> bytes:
    """
    Generate a fake but plausible VDF proof for testing when chiavdf is unavailable.

    This creates a proof with the correct structure but won't pass verification.
    Useful for testing message handling and protocol flow.
    """
    # Create deterministic fake proof based on inputs
    h = hashlib.sha256()
    h.update(challenge)
    h.update(struct.pack('<Q', iterations))
    h.update(struct.pack('<I', discriminant_size_bits))

    # Generate ~200 bytes of pseudo-random data
    proof_data = b'\x03\x00'  # Common VDF proof prefix
    for i in range(6):
        h.update(struct.pack('<I', i))
        proof_data += h.digest()

    # Trim to typical proof size
    return proof_data[:200]

def compute_pow_commitment(proof_blob: CProofBlob, use_merkle: bool = True) -> bytes:
    """
    Compute the PoW commitment (hashPoW) for a CProofBlob.

    Args:
        proof_blob: The proof blob object
        use_merkle: If True, compute Merkle root; if False, compute legacy hash

    Returns:
        32-byte commitment hash
    """
    if not use_merkle:
        # Legacy: SHA256(serialize(proof_blob))
        serialized = proof_blob.serialize()
        return hashlib.sha256(hashlib.sha256(serialized).digest()).digest()

    # Merkle root over [L_tick, L_vdf, L_meta, L_rest]
    # This is a simplified version - actual implementation in C++

    # L_tick: LeafHash(0x01, tick)
    tick_data = struct.pack('<Q', proof_blob.tick)
    l_tick = pow_leaf_hash(0x01, tick_data)

    # L_vdf: LeafHash(0x02, vdf_proof)
    l_vdf = pow_leaf_hash(0x02, proof_blob.vdf)

    # L_meta: LeafHash(0x03, version || model_hash)
    model_hash = hashlib.sha256(proof_blob.model_identifier).digest()
    meta_data = struct.pack('B', proof_blob.version) + model_hash
    l_meta = pow_leaf_hash(0x03, meta_data)

    # L_rest: LeafHash(0x04, serialize(full_blob))
    l_rest = pow_leaf_hash(0x04, proof_blob.serialize())

    # Compute Merkle root
    h01 = hash_pair(l_tick, l_vdf)
    h23 = hash_pair(l_meta, l_rest)
    root = hash_pair(h01, h23)

    return root

def pow_leaf_hash(tag: int, data: bytes) -> bytes:
    """
    Compute a tagged leaf hash for PoW Merkle tree.

    Format: SHA256(SHA256(0xFF || "POW\0" || tag || len || data))
    """
    h = hashlib.sha256()
    # Prefix: 0xFF || "POW\0" || tag
    h.update(b'\xff')
    h.update(b'POW\x00')
    h.update(struct.pack('B', tag))
    # Length (little-endian u32)
    h.update(struct.pack('<I', len(data)))
    # Data
    h.update(data)
    # Double SHA256
    return hashlib.sha256(h.digest()).digest()

def hash_pair(left: bytes, right: bytes) -> bytes:
    """Hash two 32-byte values together (Bitcoin Merkle tree style)."""
    return hashlib.sha256(hashlib.sha256(left + right).digest()).digest()

def build_merkle_branches(proof_blob: CProofBlob) -> Tuple[list, list]:
    """
    Build Merkle branches for tick and VDF leaves.

    Returns:
        (branch_for_tick, branch_for_vdf) - Each is a list of 32-byte hashes
    """
    # Compute all leaves
    tick_data = struct.pack('<Q', proof_blob.tick)
    l_tick = pow_leaf_hash(0x01, tick_data)
    l_vdf = pow_leaf_hash(0x02, proof_blob.vdf)

    model_hash = hashlib.sha256(proof_blob.model_identifier).digest()
    meta_data = struct.pack('B', proof_blob.version) + model_hash
    l_meta = pow_leaf_hash(0x03, meta_data)
    l_rest = pow_leaf_hash(0x04, proof_blob.serialize())

    # h23 = Hash(l_meta, l_rest)
    h23 = hash_pair(l_meta, l_rest)

    # Branch for tick: [l_vdf, h23]
    branch_tick = [l_vdf, h23]

    # Branch for VDF: [l_tick, h23]
    branch_vdf = [l_tick, h23]

    return branch_tick, branch_vdf

def populate_tensor_pow_fields(block, prev_block_hash: bytes, tick: int = 100000,
                               vdf_verify_active: bool = True,
                               use_real_vdf: bool = True) -> None:
    """
    Populate TensorCash PoW fields including VDF proof.

    Args:
        block: CBlock object to populate
        prev_block_hash: Previous block hash (32 bytes)
        tick: Number of VDF iterations
        vdf_verify_active: Whether VDF verification is consensus-critical
        use_real_vdf: Whether to generate real VDF proof (if available)
    """
    # Ensure block has pow field
    if not hasattr(block, 'pow'):
        block.pow = CProofBlob()

    # Set tick
    block.pow.tick = int(tick)

    parent_hash_int = getattr(block, 'hashPrevBlock', 0)
    parent_hash_hex = format(parent_hash_int, '064x')

    if parent_hash_int != 0 and block.pow.tick <= 0:
        raise ValueError("Non-genesis blocks must set a positive pow.tick before solving")

    # Best-effort cumulative_tick propagation when caller has not set it yet.
    if hasattr(block, 'cumulative_tick'):
        existing_cum = int(getattr(block, 'cumulative_tick', 0))
    else:
        existing_cum = 0
        block.cumulative_tick = 0

    parent_cum = _lookup_parent_cumulative(parent_hash_hex)

    if parent_hash_int == 0:
        # Genesis-style case: allow caller to provide custom cumulative tick (usually 0 or pow.tick).
        if block.cumulative_tick == 0:
            block.cumulative_tick = block.pow.tick
    else:
        # Non-genesis: require a known parent cumulative tick either from cache or caller input.
        if parent_cum is not None:
            expected_cum = parent_cum + block.pow.tick
            if block.cumulative_tick not in (0, expected_cum):
                raise ValueError(
                    "cumulative_tick mismatch: expected prev cumulative tick plus current tick"
                )
            block.cumulative_tick = expected_cum
        elif existing_cum != 0:
            block.cumulative_tick = existing_cum
        else:
            raise RuntimeError(
                "cumulative_tick for parent block is unknown; call set_block_tick_from_prev or "
                "ensure the parent was solved earlier so its cumulative tick is cached"
            )

        if block.cumulative_tick <= 0:
            raise ValueError("cumulative_tick must be positive for non-genesis blocks")

    # Generate VDF proof if verification is active
    if vdf_verify_active:
        if use_real_vdf:
            block.pow.vdf = generate_vdf_proof(prev_block_hash, tick)
        else:
            # Use test vector or fake proof
            block.pow.vdf = generate_fake_vdf_proof(prev_block_hash, tick, 1024)
    else:
        block.pow.vdf = b''

    if parent_hash_int != 0 and len(block.pow.vdf) == 0:
        raise ValueError("Non-genesis blocks must include a VDF proof")

    # Set model identifier
    if not block.pow.model_identifier:
        block.pow.model_identifier = b"testModel@" + hashlib.sha256(b"test").hexdigest().encode()[:40]

    # Compute and set hashPoW (Merkle root if VDF SPV active)
    use_merkle = vdf_verify_active  # Simplified: assume VDF SPV active when VDF verify active
    block.hashPoW = int.from_bytes(compute_pow_commitment(block.pow, use_merkle), 'little')

    # Ensure other TensorCash fields are set
    if not hasattr(block, 'nAdjBits') or block.nAdjBits == 0:
        block.nAdjBits = block.nBits
    if not hasattr(block, 'flags'):
        block.flags = 0

def create_headers_ext_sidecar(block_hash: bytes, prev_hash: bytes,
                               proof_blob: CProofBlob) -> dict:
    """
    Create a HEADERS_EXT sidecar structure for SPV.

    Returns:
        Dictionary with sidecar fields
    """
    pb = CProofBlob()
    pb.deserialize(BytesIO(proof_blob.serialize()))

    branch_tick, branch_vdf = build_merkle_branches(pb)

    return {
        'header_hash': block_hash,
        'prev_hash': prev_hash,
        'tick': pb.tick,
        'vdf': bytes(pb.vdf),
        'merkle_branch_tick': branch_tick,
        'merkle_branch_vdf': branch_vdf,
        'n_leaves': 4,
        'leaf_scheme_version': 1,
    }

# Export main functions
__all__ = [
    'generate_vdf_proof',
    'populate_tensor_pow_fields',
    'compute_pow_commitment',
    'create_headers_ext_sidecar',
    'cache_block_cumulative',
    'HAS_CHIAVDF',
]
