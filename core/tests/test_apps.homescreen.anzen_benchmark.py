# flake8: noqa: F403,F405
from common import *  # isort:skip

from trezor.crypto import hashlib
from trezor.crypto.curve import bip340

from apps.homescreen import anzen_benchmark


class TestAnzenBenchmark(unittest.TestCase):
    def test_fixed_signing_digest(self):
        self.assertEqual(
            anzen_benchmark.FIXED_SIGNING_DIGEST,
            hashlib.sha256(b"Anzen benchmark fixed BIP340 digest v1").digest(),
        )

    # These vectors were independently generated with rust-bitcoin 0.32.9. Its
    # TapLeafHash, TapNodeHash and TapTweak implementations build the policy,
    # while anzen-cold-signer walks the transaction graph and rust-bitcoin's
    # SighashCache checks every script-path signature message.
    def test_policy_and_sighash_vectors(self):
        vault_script_pubkey, cooperative_leaf = anzen_benchmark._policy()
        self.assertEqual(
            cooperative_leaf,
            unhexlify(
                "19a70588a0b3f3e7c014d2028ab9d60e3fdde5b25756885948ed7d6f47a6d5ac"
            ),
        )
        self.assertEqual(
            vault_script_pubkey,
            unhexlify(
                "51207746bd0987d0f99246ed8dd9a72602b25839cd69d5ed073594368f5730c366a8"
            ),
        )
        self.assertEqual(
            anzen_benchmark._controller_policy(),
            unhexlify(
                "5120ccbfe6eda160423f32be4f8e9d045840e00a13b1e22fcd3605e31cf3e8fdb109"
            ),
        )

        sighashes = anzen_benchmark.generate_sighashes()
        self.assertEqual(len(sighashes), 26)
        self.assertEqual(
            sighashes[0],
            unhexlify(
                "f8822d0163062def93d76aff8ff68e310e9b5ff74cf7b01da0ab24dc79b19cf7"
            ),
        )
        self.assertEqual(
            sighashes[-1],
            unhexlify(
                "b747e0da869f4d3b063d43486fabb53da892b4ab7029f4045b12fa22f0d74c31"
            ),
        )
        self.assertEqual(
            hashlib.sha256(b"".join(sighashes)).digest(),
            unhexlify(
                "46214a1b16f883aa7f668262078e52ed415bfae0c6a554ad125d42752c713afa"
            ),
        )

    def test_every_sighash_is_signed_by_the_real_bip340_primitive(self):
        self.assertEqual(
            bip340.publickey(anzen_benchmark._HWW_PRIVATE_KEY),
            anzen_benchmark._HWW_XONLY_PUBLIC_KEY,
        )
        for sighash in anzen_benchmark.generate_sighashes():
            signature = bip340.sign(anzen_benchmark._HWW_PRIVATE_KEY, sighash)
            self.assertTrue(
                bip340.verify(
                    anzen_benchmark._HWW_XONLY_PUBLIC_KEY,
                    signature,
                    sighash,
                )
            )

    def test_fixed_digest_is_signed_by_the_real_bip340_primitive(self):
        signature = bip340.sign(
            anzen_benchmark._HWW_PRIVATE_KEY,
            anzen_benchmark.FIXED_SIGNING_DIGEST,
        )
        self.assertTrue(
            bip340.verify(
                anzen_benchmark._HWW_XONLY_PUBLIC_KEY,
                signature,
                anzen_benchmark.FIXED_SIGNING_DIGEST,
            )
        )

    def test_runtime_benchmark_key_is_derived_without_a_device_seed(self):
        _elapsed_us, private_key, xonly_public_key = (
            anzen_benchmark._derive_benchmark_key()
        )
        self.assertEqual(bip340.publickey(private_key), xonly_public_key)


if __name__ == "__main__":
    unittest.main()
