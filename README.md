# DPKI E2E v3 — CRL / DPKI Separated Benchmark

## Purpose

CRL and DPKI are measured in separate Python processes so that CRL object
construction, memory allocation, garbage collection, and cache state do not
contaminate DPKI timing.

Only the workload definition is shared:

- total certificate population N
- revoked ratio
- deterministic revoked serial set
- random seed

This makes the comparison reproducible while keeping the execution paths isolated.

## Measurement principle

### CRL process
Measures only CRL-specific status-management costs:
- CRL object construction/signing
- DER serialization
- DER parsing
- signature verification
- CRL DER byte size

CA creation is outside the measured CRL-generation path.

### DPKI process
Measures:
- real X.509 issuance
- SQLite status registration
- Merkle leaf/tree construction
- Besu commitment proposal and independently validated anchoring
- independent pre-anchoring Merkle-root reconstruction (`C_D == C_V`)
- steady-state lookup/proof/root-read/local verification

Do NOT directly compare DPKI total initialization E2E against CRL generation
as if they represented identical workloads.

For status-management comparison, compare:
- CRL generation / CRL byte size
versus
- DPKI registry + leaf/tree + commitment / Merkle proof size

## 1. Install

```bash
pip install cryptography web3 py-solc-x
export BESU_RPC_URL=http://<BESU_RPC_HOST>:8545
export BESU_PRIVATE_KEY=0xUPDATER_TEST_KEY
export BESU_VALIDATOR_PRIVATE_KEY=0xVALIDATOR_TEST_KEY
```

Use the already deployed contract if `build/DPKICommitmentRegistry.json` exists.
Otherwise:

```bash
python deploy_contract.py
```

## 2. Prepare shared workload

100K / 10%:
```bash
python prepare_workload.py \
  --n 100000 \
  --revoke-ratio 0.10 \
  --seed 20260903 \
  --output workload_100k_10pct
```

Final 1M / 10%:
```bash
python prepare_workload.py \
  --n 1000000 \
  --revoke-ratio 0.10 \
  --seed 20260903 \
  --output workload_1m_10pct
```

## 3. Run CRL separately

Run from a fresh shell/process:

```bash
python run_crl_benchmark.py \
  --workload workload_100k_10pct \
  --repeats 5 \
  --output results_crl_100k_10pct
```

Final:

```bash
python run_crl_benchmark.py \
  --workload workload_1m_10pct \
  --repeats 5 \
  --output results_crl_1m_10pct
```

Outputs:
- raw_crl_benchmark.csv
- summary_crl_benchmark.csv
- environment_crl.json

## 4. Run DPKI separately

Use a separate fresh process:

```bash
python run_dpki_benchmark.py \
  --workload workload_100k_10pct \
  --queries 5000 \
  --warmup 500 \
  --domain D01-A \
  --output results_dpki_100k_10pct
```

Final:

```bash
python run_dpki_benchmark.py \
  --workload workload_1m_10pct \
  --queries 5000 \
  --warmup 500 \
  --domain D01-A \
  --output results_dpki_1m_10pct
```

## Recommended execution order

For the final 1M run:

1. prepare_workload.py
2. close the shell/process if desired
3. run_crl_benchmark.py
4. finish CRL process completely
5. optionally check free memory
6. run_dpki_benchmark.py in a fresh process

Do not import one benchmark from the other.
Do not run both in one Python interpreter.

## Final target

- N = 1,000,000
- revoked = 100,000
- revocation ratio = 10%
- 4-validator QBFT Besu
- same revoked serial set for CRL and DPKI

## 5. Pre-anchoring validation (v4 revision)

This revision separates the DCM/updater role from an independent validator.
The two roles MUST use different Besu accounts.

```bash
export BESU_PRIVATE_KEY=0xUPDATER_TEST_KEY
export BESU_VALIDATOR_PRIVATE_KEY=0xVALIDATOR_TEST_KEY
python deploy_contract.py
```

The deployment script authorizes the validator account in the contract. The
benchmark then performs the following sequence:

1. The DCM constructs the Merkle tree and proposes `C_D` with
   `proposeCommitment(...)`.
2. The validator opens the SQLite repository independently, reads records in
   deterministic `leaf_index` order, reconstructs the Merkle tree, and derives
   `C_V`.
3. The validator submits `C_V` using `validateAndCommit(...)`.
4. The smart contract anchors the commitment only when `C_D == C_V`; a mismatch causes the validation transaction to revert with `commitment validation failed`.
5. Post-anchoring verification continues to use the repository record, Merkle
   proof, and blockchain-anchored commitment.

The smart contract intentionally does not parse X.509 objects or reconstruct a
Merkle tree on-chain. Repository/status validation and Merkle reconstruction
remain off-chain; the contract acts as the authorization and validation gate.

Additional initialization metrics include proposal latency/gas, independent
validator reconstruction time, validation latency/gas, and the pre-anchor root
match result.

### Trust assumption

The independent validator requires read access to the same committed PKI
repository snapshot. A CRL alone is not sufficient to reconstruct this
benchmark's complete tree because the tree contains both VALID and REVOKED
certificate-status records.


### Negative validation behavior

If the validator submits a root different from the DCM-proposed root,
`validateAndCommit(...)` reverts with `commitment validation failed`. The pending
proposal remains unanchored, so an inconsistent directory commitment cannot become
the latest blockchain commitment. This behavior can be used as a negative test for
the pre-anchoring validation mechanism.

## Public repository configuration

The repository intentionally contains no private keys, deployed contract addresses,
transaction hashes, or private-network RPC endpoints. Configure a local/test Besu
endpoint and two distinct funded test accounts through environment variables.

```bash
export BESU_RPC_URL=http://<BESU_RPC_HOST>:8545
export BESU_PRIVATE_KEY=0xUPDATER_TEST_PRIVATE_KEY
export BESU_VALIDATOR_PRIVATE_KEY=0xVALIDATOR_TEST_PRIVATE_KEY
```

Deployment artifacts under `build/`, generated workloads, SQLite databases, and
benchmark result directories are excluded by `.gitignore`.

### Negative pre-anchoring validation test

After deployment, an intentionally mismatching validator root can be tested with:

```bash
python negative_commitment_test.py \
  --contract 0xYOUR_DEPLOYED_CONTRACT_ADDRESS \
  --artifact build/DPKICommitmentRegistry.json
```

A successful negative test reports both `Mismatch rejected: True` and
`Anchored state unchanged: True`.
