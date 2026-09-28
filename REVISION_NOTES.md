# Revision notes — pre-anchoring validation

Changes made for the revised DPKI trust model:

- Replaced direct `commit()` anchoring with a two-step flow:
  `proposeCommitment()` -> `validateAndCommit()`.
- Separated `authorizedUpdater` and `authorizedValidator` roles.
- Required different Besu accounts for updater and validator in deployment and benchmark scripts.
- Added independent validator reconstruction of `C_V` using a separate SQLite connection and deterministic `leaf_index` ordering.
- The contract records the commitment only when the proposed `C_D` equals independently reconstructed `C_V`.
- Preserved post-anchoring Merkle proof verification against the root read from Besu.
- Added initialization metrics for proposal, validator reconstruction, validation transaction, and root-match result.

Scope note: the validator independently reads the same PKI repository snapshot. The current benchmark tree includes both VALID and REVOKED records, so a CRL alone cannot reproduce the full commitment.

- Changed mismatched pre-anchoring validation from a successful transaction returning `0` to an explicit smart-contract revert (`commitment validation failed`). This makes rejection observable at the transaction level and leaves the inconsistent proposal unanchored.
