#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, gc, hashlib, json, math, os, random, sqlite3, statistics, sys, time, platform
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from web3 import Web3

def h(x): return hashlib.sha256(x).digest()
def parent_hash(a,b): return h(b"\x01"+a+b)
def leaf_hash(cert_id,status): return h(b"\x00"+cert_id.encode()+b"|"+status.encode())

class MerkleTree:
    def __init__(self, leaves):
        self.levels=[leaves]
        level=leaves
        while len(level)>1:
            nxt=[]
            for i in range(0,len(level),2):
                a=level[i]; b=level[i+1] if i+1<len(level) else a
                nxt.append(parent_hash(a,b))
            self.levels.append(nxt); level=nxt
    @property
    def root(self): return self.levels[-1][0]
    @property
    def depth(self): return len(self.levels)-1
    def proof(self,index):
        out=[]; idx=index
        for level in self.levels[:-1]:
            if idx%2==0:
                sib=idx+1 if idx+1<len(level) else idx
                out.append(("R",level[sib]))
            else:
                out.append(("L",level[idx-1]))
            idx//=2
        return out

def verify(leaf,index,proof,root):
    cur=leaf
    for side,sib in proof:
        cur=parent_hash(sib,cur) if side=="L" else parent_hash(cur,sib)
    return cur==root

def create_ca():
    key=ec.generate_private_key(ec.SECP256R1())
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,"KR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,"DPKI Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME,"D01-A Root CA")])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(minutes=1))
          .not_valid_after(now+timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
          .sign(key,hashes.SHA256()))
    return key,cert

def issue_cert(ca_key,ca_cert,serial):
    key=ec.generate_private_key(ec.SECP256R1())
    now=datetime.now(timezone.utc)
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,"KR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,"DPKI Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME,f"ee-{serial:08d}.example")])
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject)
          .public_key(key.public_key()).serial_number(serial)
          .not_valid_before(now-timedelta(minutes=1))
          .not_valid_after(now+timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .sign(ca_key,hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)

def load_contract(w3,path):
    a=json.loads(Path(path).read_text(encoding="utf-8"))
    return w3.eth.contract(address=Web3.to_checksum_address(a["address"]),abi=a["abi"])

def percentile(xs,p):
    s=sorted(xs); return s[max(0,min(len(s)-1,math.ceil(p*len(s))-1))]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--workload", required=True)
    ap.add_argument("--queries", type=int, default=5000)
    ap.add_argument("--warmup", type=int, default=500)
    ap.add_argument("--domain", default="D01-A")
    ap.add_argument("--output", default="results_dpki")
    ap.add_argument("--rpc", default=os.getenv("BESU_RPC_URL"), help="Besu JSON-RPC endpoint (or set BESU_RPC_URL)")
    ap.add_argument("--private-key", default=os.getenv("BESU_PRIVATE_KEY"),
                    help="DCM/updater private key")
    ap.add_argument("--validator-private-key", default=os.getenv("BESU_VALIDATOR_PRIVATE_KEY"),
                    help="Independent validator private key")
    ap.add_argument("--artifact", default="build/DPKICommitmentRegistry.json")
    args=ap.parse_args()
    if not args.rpc:
        raise SystemExit("Besu JSON-RPC endpoint required: use --rpc or BESU_RPC_URL")

    if not args.private_key:
        raise SystemExit("BESU_PRIVATE_KEY required")
    if not args.validator_private_key:
        raise SystemExit("BESU_VALIDATOR_PRIVATE_KEY required")

    wp=Path(args.workload)
    meta=json.loads((wp/"workload.json").read_text())
    revoked={int(r["serial"]) for r in csv.DictReader((wp/"revoked_serials.csv").open())}
    n=int(meta["n"])
    if len(revoked)!=round(n*float(meta["revoke_ratio"])):
        raise RuntimeError("revocation-count validation failed")

    out=Path(args.output); out.mkdir(parents=True,exist_ok=True)
    init={}; e2e0=time.perf_counter_ns()

    t=time.perf_counter_ns(); ca_key,ca_cert=create_ca()
    init["root_ca_generation_ms"]=(time.perf_counter_ns()-t)/1e6

    rows=[]
    t=time.perf_counter_ns()
    for serial in range(1,n+1):
        der=issue_cert(ca_key,ca_cert,serial)
        status="REVOKED" if serial in revoked else "VALID"
        rows.append((f"CERT-{serial:08d}",serial,status,serial-1,hashlib.sha256(der).hexdigest()))
        if serial%100000==0:
            print(f"issued {serial:,}/{n:,}",flush=True)
    init["certificate_generation_ms"]=(time.perf_counter_ns()-t)/1e6
    init["certificate_generation_ms_per_cert"]=init["certificate_generation_ms"]/n

    dbp=out/"directory.sqlite3"
    if dbp.exists(): dbp.unlink()
    db=sqlite3.connect(dbp)
    db.execute("""CREATE TABLE certificate_status(
      cert_id TEXT PRIMARY KEY, serial INTEGER NOT NULL, status TEXT NOT NULL,
      leaf_index INTEGER NOT NULL, cert_sha256 TEXT NOT NULL)""")
    t=time.perf_counter_ns()
    db.executemany("INSERT INTO certificate_status VALUES(?,?,?,?,?)",rows); db.commit()
    init["status_registry_registration_ms"]=(time.perf_counter_ns()-t)/1e6

    t=time.perf_counter_ns()
    leaves=[leaf_hash(r[0],r[2]) for r in rows]
    init["leaf_generation_ms"]=(time.perf_counter_ns()-t)/1e6

    t=time.perf_counter_ns(); tree=MerkleTree(leaves)
    init["merkle_tree_build_ms"]=(time.perf_counter_ns()-t)/1e6
    init["merkle_depth"]=tree.depth

    w3=Web3(Web3.HTTPProvider(args.rpc,request_kwargs={"timeout":120}))
    _=w3.eth.chain_id
    updater=w3.eth.account.from_key(args.private_key)
    validator=w3.eth.account.from_key(args.validator_private_key)
    if updater.address.lower()==validator.address.lower():
        raise RuntimeError("updater and validator must use different Besu accounts")
    contract=load_contract(w3,args.artifact)
    domain_id=Web3.keccak(text=args.domain)

    if not contract.functions.authorizedUpdater(updater.address).call():
        raise RuntimeError("updater account is not authorized by the contract")
    if not contract.functions.authorizedValidator(validator.address).call():
        raise RuntimeError("validator account is not authorized by the contract")

    # DCM proposes C_D. The proposal is pending and is not yet anchored.
    propose_tx=contract.functions.proposeCommitment(
        domain_id,tree.root,n,len(revoked)).build_transaction({
        "from":updater.address,
        "nonce":w3.eth.get_transaction_count(updater.address,"pending"),
        "chainId":w3.eth.chain_id,"gasPrice":0,"gas":300000
    })
    t=time.perf_counter_ns(); signed=updater.sign_transaction(propose_tx)
    init["besu_proposal_sign_ms"]=(time.perf_counter_ns()-t)/1e6
    t=time.perf_counter_ns(); txh=w3.eth.send_raw_transaction(signed.raw_transaction)
    init["besu_proposal_submit_ms"]=(time.perf_counter_ns()-t)/1e6
    t=time.perf_counter_ns(); proposal_receipt=w3.eth.wait_for_transaction_receipt(txh,timeout=120)
    init["besu_proposal_confirmation_ms"]=(time.perf_counter_ns()-t)/1e6
    init["besu_proposal_gas_used"]=proposal_receipt.gasUsed
    if proposal_receipt.status!=1: raise RuntimeError("commitment proposal failed")

    # Independent pre-anchoring validation: reopen the repository through a
    # separate SQLite connection and reconstruct C_V deterministically.
    validator_db=sqlite3.connect(dbp)
    t=time.perf_counter_ns()
    validator_rows=validator_db.execute(
        "SELECT cert_id,status FROM certificate_status ORDER BY leaf_index").fetchall()
    validator_leaves=[leaf_hash(cert_id,status) for cert_id,status in validator_rows]
    validator_tree=MerkleTree(validator_leaves)
    init["validator_commitment_reconstruction_ms"]=(time.perf_counter_ns()-t)/1e6
    validator_db.close()
    validated_root=validator_tree.root
    init["pre_anchor_root_match"]=int(validated_root==tree.root)
    if validated_root!=tree.root:
        raise RuntimeError("pre-anchoring validation failed: C_D != C_V")

    # Validator submits C_V. The smart contract anchors only when C_D == C_V.
    validate_tx=contract.functions.validateAndCommit(
        domain_id,validated_root).build_transaction({
        "from":validator.address,
        "nonce":w3.eth.get_transaction_count(validator.address,"pending"),
        "chainId":w3.eth.chain_id,"gasPrice":0,"gas":300000
    })
    t=time.perf_counter_ns(); signed_v=validator.sign_transaction(validate_tx)
    init["besu_validation_sign_ms"]=(time.perf_counter_ns()-t)/1e6
    t=time.perf_counter_ns(); vh=w3.eth.send_raw_transaction(signed_v.raw_transaction)
    init["besu_validation_submit_ms"]=(time.perf_counter_ns()-t)/1e6
    t=time.perf_counter_ns(); receipt=w3.eth.wait_for_transaction_receipt(vh,timeout=120)
    init["besu_validation_confirmation_ms"]=(time.perf_counter_ns()-t)/1e6
    init["besu_validation_gas_used"]=receipt.gasUsed
    init["besu_block_number"]=receipt.blockNumber
    if receipt.status!=1: raise RuntimeError("validated commitment anchoring failed")

    anchored=bytes(contract.functions.getCommitment(domain_id).call()[0])
    if anchored!=tree.root: raise RuntimeError("validated root was not anchored")
    init["initialization_e2e_ms"]=(time.perf_counter_ns()-e2e0)/1e6

    rng=random.Random(int(meta["seed"]))
    for _ in range(args.warmup):
        idx=rng.randrange(n); cid=f"CERT-{idx+1:08d}"
        status,li=db.execute("SELECT status,leaf_index FROM certificate_status WHERE cert_id=?",(cid,)).fetchone()
        p=tree.proof(li); assert verify(leaves[li],li,p,tree.root)

    raw=[]
    was_gc=gc.isenabled()
    if was_gc: gc.disable()
    try:
        for q in range(1,args.queries+1):
            idx=rng.randrange(n); cid=f"CERT-{idx+1:08d}"; e0=time.perf_counter_ns()
            t=time.perf_counter_ns()
            status,li=db.execute("SELECT status,leaf_index FROM certificate_status WHERE cert_id=?",(cid,)).fetchone()
            lookup=(time.perf_counter_ns()-t)/1e3
            t=time.perf_counter_ns(); proof=tree.proof(li); proof_us=(time.perf_counter_ns()-t)/1e3
            t=time.perf_counter_ns()
            payload=json.dumps({"id":cid,"status":status,"proof":[(s,hx.hex()) for s,hx in proof]},
                               separators=(",",":")).encode()
            ser_us=(time.perf_counter_ns()-t)/1e3
            t=time.perf_counter_ns(); onchain=bytes(contract.functions.getCommitment(domain_id).call()[0])
            root_ms=(time.perf_counter_ns()-t)/1e6
            if onchain!=tree.root: raise RuntimeError("on-chain root mismatch")
            t=time.perf_counter_ns(); ok=verify(leaves[li],li,proof,onchain)
            verify_us=(time.perf_counter_ns()-t)/1e3
            if not ok: raise RuntimeError("proof verify failed")
            raw.append({
                "query":q,"status":status,"tree_depth":tree.depth,"proof_hashes":len(proof),
                "proof_json_bytes":len(payload),"sqlite_lookup_us":lookup,
                "proof_generation_us":proof_us,"serialization_us":ser_us,
                "besu_root_read_ms":root_ms,"proof_verification_us":verify_us,
                "verification_e2e_ms":(time.perf_counter_ns()-e0)/1e6
            })
    finally:
        if was_gc: gc.enable()

    with (out/"initialization_metrics.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["metric","value"]); w.writerows(init.items())
    with (out/"raw_verification_queries.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=raw[0].keys()); w.writeheader(); w.writerows(raw)

    summary=[]
    for field,unit in [("sqlite_lookup_us","us"),("proof_generation_us","us"),
        ("serialization_us","us"),("besu_root_read_ms","ms"),
        ("proof_verification_us","us"),("verification_e2e_ms","ms")]:
        xs=[float(r[field]) for r in raw]
        summary.append({
            "metric":field,"unit":unit,"mean":statistics.fmean(xs),
            "median":statistics.median(xs),"p95":percentile(xs,.95),
            "p99":percentile(xs,.99),"min":min(xs),"max":max(xs)
        })
    with (out/"summary_verification_queries.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=summary[0].keys()); w.writeheader(); w.writerows(summary)

    env={"python":sys.version.replace("\n"," "),"platform":platform.platform(),
         "workload":meta,"rpc":args.rpc,"chain_id":w3.eth.chain_id,
         "contract":contract.address,"updater":updater.address,"validator":validator.address,
         "pre_anchoring_validation":"independent SQLite read + deterministic Merkle reconstruction",
         "queries":args.queries,"warmup":args.warmup}
    (out/"environment_dpki.json").write_text(json.dumps(env,indent=2),encoding="utf-8")
    db.close()

if __name__=="__main__":
    main()
