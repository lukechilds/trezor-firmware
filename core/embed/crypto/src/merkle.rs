use super::sha256;
use crate::init_ctx;

/// Calculate a Merkle root based on a leaf element and a proof of inclusion.
///
/// Expects the Merkle tree format specified in `external-definitions.md`.
pub fn merkle_root(elem: &[u8], proof: &[sha256::Digest]) -> sha256::Digest {
    init_ctx!(ctx);
    // hash the leaf element
    let mut sha = sha256::sha256_new(ctx);
    sha.update(&[0x00]);
    sha.update(elem);
    let mut out = sha.finalize();

    for proof_elem in proof {
        // hash together the current hash and the proof element
        let (min, max) = if out.as_ref() < proof_elem.as_ref() {
            (&out, proof_elem)
        } else {
            (proof_elem, &out)
        };
        init_ctx!(ctx);
        let mut sha = sha256::sha256_new(ctx);
        sha.update(&[0x01]);
        sha.update(min.as_ref());
        sha.update(max.as_ref());
        out = sha.finalize();
    }

    out
}
