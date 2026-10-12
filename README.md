# DPKI — Verifiable Certificate Status Management

Research prototype and reproducibility materials for **A DPKI Architecture with Blockchain-Based Directory Commitments for Verifiable Certificate Status Management**.

The prototype preserves X.509 PKI trust semantics and uses a SQLite status repository, deterministic Merkle commitments, and a QBFT-based Hyperledger Besu smart contract. An independent validator reconstructs the proposed commitment before anchoring. The blockchain does not validate X.509 certificates or hold private keys.

## Reproducibility data

The `results/` directory contains the **September 28, 2026** evaluation results used for the manuscript. Each scale uses N = 100, 1,000, 10,000, or 100,000 certificates with 10% revoked certificates, and ten independent runs.

| Manuscript result | Public data |
| --- | --- |
| Figure 3: CRL generation, signature verification, DER size | `results/crl_<N>/raw_crl_benchmark.csv`, `summary_crl_benchmark.csv` |
| Figure 3: DPKI commitment, proof generation/verification, sibling bytes | `results/repository_<N>/raw_repository_runs.csv`, `raw_repository_queries.csv`, `summary_repository.csv` |
| Figure 4(a): commitment generation and independent pre-anchoring reconstruction | Repository summaries and `results/besu_scale/n_<N>/summary_besu_runs.csv` |
| Figure 4(b): QBFT proposal/validation/anchoring latency | `results/besu_scale/n_<N>/raw_besu_runs.csv`, `summary_besu_runs.csv` |
| Figure 4(c): post-anchoring proof generation, proof verification, root retrieval | `results/besu_scale/n_<N>/run_01` through `run_10/raw_verification_queries.csv` |
| CPU and peak resident memory (N=100,000) | `resource_100k/resource_summary.csv` |

For Figure 4(c), calculate the per-run mean over each run's 5,000 verification queries, then report the mean and sample standard deviation over ten independent run-level means. **Do not substitute** standalone repository proof timings for Besu-integrated verification timings.

These are benchmark measurements, not an export of a production PKI. Workloads can be regenerated deterministically using `prepare_workload.py`; SQLite databases and private network configuration are intentionally not distributed. Results may be analyzed without access to the original Besu node. Re-executing the on-chain benchmark requires a separately configured Besu network.

## Setup

Python and dependencies:

```bash
python -m pip install -r requirements.txt
```

Configure a **local or disposable test** Besu QBFT network, deploy the contract, and provide two distinct funded test accounts. Never use production private keys.

```bash
export BESU_RPC_URL="http://127.0.0.1:8545"
export BESU_PRIVATE_KEY="<TEST_UPDATER_PRIVATE_KEY>"
export BESU_VALIDATOR_PRIVATE_KEY="<TEST_VALIDATOR_PRIVATE_KEY>"
python deploy_contract.py
```

The deployment artifact is generated locally under `build/` and is not committed.

## Reproduce the benchmark

Prepare workloads for all four scales, using the same deterministic seed and revocation ratio:

```bash
for n in 100 1000 10000 100000; do
  python prepare_workload.py --n "$n" --revoke-ratio 0.10 --seed 42 --output "workload_$n"
done
```

Run CRL and repository measurements in **separate Python processes** to avoid cache and allocation interference:

```bash
for n in 100 1000 10000 100000; do
  python run_crl_benchmark.py --workload "workload_$n" --repeats 10 --output "results/crl_$n"
  python run_repository_benchmark.py --workload "workload_$n" --repeats 10 --output "results/repository_$n"
done
```

With a deployed contract and test network:

```bash
python run_besu_scale_suite.py --repeats 10 --queries 5000 --warmup 500 --output results/besu_scale
```

The on-chain procedure is: propose the directory commitment; independently reconstruct the Merkle root from the repository snapshot; submit the validator's root; anchor only if both roots match; then verify Merkle proofs against the anchored commitment. The negative-path test is available in `negative_commitment_test.py`.

### Measurement boundaries

- CRL generation excludes CA creation.
- DPKI repository commitment generation and Besu anchoring are separate stages.
- Besu confirmation latency depends on the network and is not expected to reproduce bit-for-bit.
- CPU and memory are host- and runtime-dependent.
- The public dataset contains measured CSVs, not original certificate/private-key material or generated SQLite snapshots.

## Security and publication hygiene

Do not commit RPC hostnames or IP addresses, account addresses from private networks, contract deployments, transaction identifiers, private keys, local absolute paths, or database snapshots. Environment variables and `.env.example` provide configuration placeholders. Historical commits may still contain values removed from the current tree; removing files in a PR does **not** erase Git history. If an exposed endpoint or credential is still active, rotate or restrict it separately.
