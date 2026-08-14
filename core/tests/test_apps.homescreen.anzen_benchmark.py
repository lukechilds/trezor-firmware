# flake8: noqa: F403,F405
from common import *  # isort:skip

from trezor.crypto import hashlib
from trezor.crypto.curve import bip340

from apps.homescreen import anzen_benchmark


class TestAnzenBenchmark(unittest.TestCase):
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

        sighashes = anzen_benchmark.generate_sighashes()
        self.assertEqual(len(sighashes), 39)
        self.assertEqual(
            sighashes[0],
            unhexlify(
                "b97d4d2065bdb3bd79e8084297e28f687788894fa3272bb464051f343805edb7"
            ),
        )
        self.assertEqual(
            sighashes[-1],
            unhexlify(
                "773e220f7338b8f2daa46cb6f32ec541f61566288ceabdd70167a962576ed926"
            ),
        )
        self.assertEqual(
            hashlib.sha256(b"".join(sighashes)).digest(),
            unhexlify(
                "94bda797a8c0fdc80f9108755eecc92eba0ce0700ff91ee5f57e3fbea190ced5"
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


if __name__ == "__main__":
    unittest.main()
