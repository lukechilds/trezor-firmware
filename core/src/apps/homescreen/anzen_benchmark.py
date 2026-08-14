"""Deterministic Anzen annual-policy signing benchmark.

The transactions in this module use fake outpoints and fixed benchmark keys. The
graph matches ``vault/cold-signer/src/benchmark.rs`` and the policy commitments
and script-path signature messages follow BIP341.
"""

import gc
import utime
from micropython import const
from ubinascii import unhexlify

from trezor.crypto import hashlib
from trezor.crypto.curve import bip340

VAULT_BALANCE_SATS = const(210_000_000)
MONTHLY_ALLOWANCE_SATS = const(10_000_000)
EMERGENCY_ACCESS_SATS = const(50_000_000)
MONTHLY_STEPS = const(12)
ROLLOVER_INPUT_COUNT = const(12)
TRANSACTION_COUNT = const(28)
SIGNATURE_COUNT = const(39)

_MONTHLY_DELAY_SEQUENCE = const((1 << 22) | 5_063)
_EMERGENCY_DELAY_SEQUENCE = const((1 << 22) | 1_182)
_PHONE_RECOVERY_BLOCKS = const(61_200)
_HWW_RECOVERY_BLOCKS = const(65_535)
_P2TR_SCRIPT_LEN = const(34)
_COOPERATIVE_SCRIPT_LEN = const(70)
_COOPERATIVE_CONTROL_BLOCK_LEN = const(65)

# These are intentionally public, trivial benchmark keys. They must never receive funds.
_PHONE_XONLY_PUBLIC_KEY = unhexlify(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
_HWW_PRIVATE_KEY = unhexlify(
    "0000000000000000000000000000000000000000000000000000000000000002"
)
_HWW_XONLY_PUBLIC_KEY = unhexlify(
    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)
_BIP341_NUMS_XONLY = unhexlify(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

_TAPLEAF_TAG_HASH = unhexlify(
    "aeea8fdc4208983105734b58081d1e2638d35f1cb54008d4d357ca03be78e9ee"
)
_TAPBRANCH_TAG_HASH = unhexlify(
    "1941a1f2e56eb95fa2a9f194be5c01f7216f33ed82b091463490d05bf516a015"
)
_TAPSIGHASH_TAG_HASH = unhexlify(
    "f40a48df4b2a70c8b4924bf2654661ed3d95fd66a313eb87237597c628e4a031"
)


def _sha256(*parts: bytes) -> bytes:
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(part)
    return hasher.digest()


def _tagged_hash(tag_hash: bytes, *parts: bytes) -> bytes:
    return _sha256(tag_hash, tag_hash, *parts)


def _tapleaf_hash(script: bytes) -> bytes:
    assert len(script) < 253
    return _tagged_hash(_TAPLEAF_TAG_HASH, b"\xc0", bytes([len(script)]), script)


def _tapbranch_hash(left: bytes, right: bytes) -> bytes:
    if left > right:
        left, right = right, left
    return _tagged_hash(_TAPBRANCH_TAG_HASH, left, right)


def _cooperative_script() -> bytes:
    return (
        b"\x20"
        + _PHONE_XONLY_PUBLIC_KEY
        + b"\xac\x20"
        + _HWW_XONLY_PUBLIC_KEY
        + b"\xba\x52\x9c"
    )


def _recovery_script(key: bytes, delay: int) -> bytes:
    # Both configured delays need a third zero byte to remain positive Script numbers.
    return (
        b"\x03" + bytes([delay & 0xFF, delay >> 8, 0]) + b"\xb2\x69\x20" + key + b"\xac"
    )


def _policy() -> tuple[bytes, bytes]:
    cooperative_leaf = _tapleaf_hash(_cooperative_script())
    phone_recovery = _tapleaf_hash(
        _recovery_script(_PHONE_XONLY_PUBLIC_KEY, _PHONE_RECOVERY_BLOCKS)
    )
    hww_recovery = _tapleaf_hash(
        _recovery_script(_HWW_XONLY_PUBLIC_KEY, _HWW_RECOVERY_BLOCKS)
    )
    recoveries = _tapbranch_hash(phone_recovery, hww_recovery)
    merkle_root = _tapbranch_hash(cooperative_leaf, recoveries)
    output_key = bip340.tweak_public_key(_BIP341_NUMS_XONLY, merkle_root)
    return b"\x51\x20" + output_key, cooperative_leaf


def _cooperative_vsize(input_count: int, output_count: int) -> int:
    base_size = 4 + 1 + input_count * 41 + 1 + output_count * 43 + 4
    witness_per_input = (
        1
        + 2 * (1 + 64)
        + 1
        + _COOPERATIVE_SCRIPT_LEN
        + 1
        + _COOPERATIVE_CONTROL_BLOCK_LEN
    )
    witness_size = 2 + input_count * witness_per_input
    return (base_size * 4 + witness_size + 3) // 4


# An input is (previous_txid, previous_vout, amount_sats, sequence).
# An output is (amount_sats, script_pubkey), and a transaction is (inputs, outputs).


def _serialize_outputs(outputs: tuple[tuple[int, bytes], ...]) -> bytes:
    result = bytearray()
    for amount, script_pubkey in outputs:
        result.extend(amount.to_bytes(8, "little"))
        result.append(len(script_pubkey))
        result.extend(script_pubkey)
    return bytes(result)


def _serialize_transaction(
    transaction: tuple[
        tuple[tuple[bytes, int, int, int], ...], tuple[tuple[int, bytes], ...]
    ],
) -> bytes:
    inputs, outputs = transaction
    result = bytearray(b"\x02\x00\x00\x00")
    result.append(len(inputs))
    for previous_txid, previous_vout, _amount, sequence in inputs:
        result.extend(previous_txid)
        result.extend(previous_vout.to_bytes(4, "little"))
        result.append(0)  # Empty scriptSig.
        result.extend(sequence.to_bytes(4, "little"))
    result.append(len(outputs))
    result.extend(_serialize_outputs(outputs))
    result.extend(b"\x00\x00\x00\x00")
    return bytes(result)


def _transaction_id(
    transaction: tuple[
        tuple[tuple[bytes, int, int, int], ...], tuple[tuple[int, bytes], ...]
    ],
) -> bytes:
    first = _sha256(_serialize_transaction(transaction))
    return _sha256(first)


def _append_sighashes(
    result: list[bytes],
    transaction: tuple[
        tuple[tuple[bytes, int, int, int], ...], tuple[tuple[int, bytes], ...]
    ],
    vault_script_pubkey: bytes,
    cooperative_leaf_hash: bytes,
) -> None:
    inputs, outputs = transaction
    prevouts = bytearray()
    amounts = bytearray()
    script_pubkeys = bytearray()
    sequences = bytearray()
    for previous_txid, previous_vout, amount, sequence in inputs:
        prevouts.extend(previous_txid)
        prevouts.extend(previous_vout.to_bytes(4, "little"))
        amounts.extend(amount.to_bytes(8, "little"))
        script_pubkeys.append(_P2TR_SCRIPT_LEN)
        script_pubkeys.extend(vault_script_pubkey)
        sequences.extend(sequence.to_bytes(4, "little"))

    common = (
        b"\x00\x00"  # Taproot epoch and SIGHASH_DEFAULT.
        + b"\x02\x00\x00\x00"  # Transaction version 2.
        + b"\x00\x00\x00\x00"  # Lock time 0.
        + _sha256(bytes(prevouts))
        + _sha256(bytes(amounts))
        + _sha256(bytes(script_pubkeys))
        + _sha256(bytes(sequences))
        + _sha256(_serialize_outputs(outputs))
        + b"\x02"  # ext_flag=1 (script path), no annex.
    )
    extension = cooperative_leaf_hash + b"\x00\xff\xff\xff\xff"
    for input_index in range(len(inputs)):
        message = common + input_index.to_bytes(4, "little") + extension
        result.append(_tagged_hash(_TAPSIGHASH_TAG_HASH, message))


def generate_sighashes() -> list[bytes]:
    """Generate all 39 BIP341 script-path digests in vault signing order."""
    vault_script_pubkey, cooperative_leaf_hash = _policy()
    result: list[bytes] = []
    transaction_count = 0

    rollover_input_value = VAULT_BALANCE_SATS // ROLLOVER_INPUT_COUNT
    rollover_input_remainder = VAULT_BALANCE_SATS % ROLLOVER_INPUT_COUNT
    rollover_inputs = tuple(
        (
            _sha256(b"Anzen benchmark fake UTXO v1", bytes([index])),
            0,
            rollover_input_value + (rollover_input_remainder if index == 0 else 0),
            0xFFFFFFFF,
        )
        for index in range(ROLLOVER_INPUT_COUNT)
    )
    continuing_fee = _cooperative_vsize(1, 2)
    final_fee = _cooperative_vsize(1, 1)
    allowance_value = (
        MONTHLY_ALLOWANCE_SATS * MONTHLY_STEPS
        + continuing_fee * (MONTHLY_STEPS - 1)
        + final_fee
    )
    rollover_fee = _cooperative_vsize(len(rollover_inputs), 2)
    rollover_remainder = VAULT_BALANCE_SATS - allowance_value - rollover_fee
    rollover = (
        rollover_inputs,
        (
            (allowance_value, vault_script_pubkey),
            (rollover_remainder, vault_script_pubkey),
        ),
    )
    _append_sighashes(result, rollover, vault_script_pubkey, cooperative_leaf_hash)
    transaction_count += 1
    rollover_txid = _transaction_id(rollover)

    chain_input = (
        rollover_txid,
        0,
        allowance_value,
        _MONTHLY_DELAY_SEQUENCE,
    )
    for index in range(MONTHLY_STEPS):
        has_next = index + 1 < MONTHLY_STEPS
        authorization_fee = continuing_fee if has_next else final_fee
        next_chain_value = chain_input[2] - MONTHLY_ALLOWANCE_SATS - authorization_fee
        index_byte = bytes([index])
        hot_script = b"\x51\x20" + _sha256(
            b"Anzen benchmark monthly hot output v1", index_byte
        )
        hot_output = (MONTHLY_ALLOWANCE_SATS, hot_script)
        authorization_outputs = (
            (hot_output, (next_chain_value, vault_script_pubkey))
            if has_next
            else (hot_output,)
        )
        assert has_next or next_chain_value == 0
        authorization = ((chain_input,), authorization_outputs)
        _append_sighashes(
            result, authorization, vault_script_pubkey, cooperative_leaf_hash
        )
        transaction_count += 1
        authorization_txid = _transaction_id(authorization)

        revocation_input = (
            chain_input[0],
            chain_input[1],
            chain_input[2],
            0xFFFFFFFF,
        )
        revocation = (
            (revocation_input,),
            ((chain_input[2] - final_fee, vault_script_pubkey),),
        )
        _append_sighashes(
            result, revocation, vault_script_pubkey, cooperative_leaf_hash
        )
        transaction_count += 1

        if has_next:
            chain_input = (
                authorization_txid,
                1,
                next_chain_value,
                _MONTHLY_DELAY_SEQUENCE,
            )

    staging_value = EMERGENCY_ACCESS_SATS + final_fee
    trigger_fee = continuing_fee
    vault_change = rollover_remainder - staging_value - trigger_fee
    trigger = (
        ((rollover_txid, 1, rollover_remainder, 0xFFFFFFFF),),
        (
            (staging_value, vault_script_pubkey),
            (vault_change, vault_script_pubkey),
        ),
    )
    _append_sighashes(result, trigger, vault_script_pubkey, cooperative_leaf_hash)
    transaction_count += 1
    trigger_txid = _transaction_id(trigger)

    emergency_input = (
        trigger_txid,
        0,
        staging_value,
        _EMERGENCY_DELAY_SEQUENCE,
    )
    emergency_hot_script = b"\x51\x20" + _sha256(
        b"Anzen benchmark emergency hot output v1"
    )
    withdrawal = (
        (emergency_input,),
        ((EMERGENCY_ACCESS_SATS, emergency_hot_script),),
    )
    _append_sighashes(result, withdrawal, vault_script_pubkey, cooperative_leaf_hash)
    transaction_count += 1

    cancellation_input = (
        emergency_input[0],
        emergency_input[1],
        emergency_input[2],
        0xFFFFFFFF,
    )
    cancellation = (
        (cancellation_input,),
        ((staging_value - final_fee, vault_script_pubkey),),
    )
    _append_sighashes(result, cancellation, vault_script_pubkey, cooperative_leaf_hash)
    transaction_count += 1

    assert transaction_count == TRANSACTION_COUNT
    assert len(result) == SIGNATURE_COUNT
    return result


def run() -> tuple[int, int]:
    """Return ``(graph_time_us, signing_time_us)`` for one annual policy."""
    gc.collect()
    started_us = utime.ticks_us()
    sighashes = generate_sighashes()
    graph_time_us = utime.ticks_diff(utime.ticks_us(), started_us)

    gc.collect()
    started_us = utime.ticks_us()
    for sighash in sighashes:
        signature = bip340.sign(_HWW_PRIVATE_KEY, sighash)
        assert len(signature) == 64
    signing_time_us = utime.ticks_diff(utime.ticks_us(), started_us)

    return graph_time_us, signing_time_us
