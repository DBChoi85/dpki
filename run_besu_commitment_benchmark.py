#!/usr/bin/env python3
from __future__ import annotations
import argparse,csv,hashlib,json,os,random,sqlite3,time
from pathlib import Path
from web3 import Web3
def h(x): return hashlib.sha256(x).digest()
def ph(a,b): return h(b"\x01"+a+b)
def lh(cid,status): return h(b"\x00"+cid.encode()+b"|"+status.encode())
class MT:
    def __init__(self,leaves):
        self.levels=[leaves]; level=leaves
        while len(level)>1:
            nxt=[]
            for i in range(0,len(level),2):
                a=level[i]; b=level[i+1] if i+1<len(level) else a; nxt.append(ph(a,b))
            self.levels.append(nxt); level=nxt
    @property
    def root(self): return self.levels[-1][0]
    @property
    def depth(self): return len(self.levels)-1
    def proof(self,i):
        out=[]
        for level in self.levels[:-1]:
            if i%2==0:
                j=i+1 if i+1<len(level) else i; out.append(("R",level[j]))
            else: out.append(("L",level[i-1]))
            i//=2
        return out
def verify(leaf,proof,root):
    cur=leaf
    for side,sib in proof: cur=ph(sib,cur) if side=="L" else ph(cur,sib)
    return cur==root
def send(w3,fn,acct):
    tx=fn.build_transaction({"from":acct.address,"nonce":w3.eth.get_transaction_count(acct.address,"pending"),"chainId":w3.eth.chain_id,"gasPrice":0,"gas":300000})
    t=time.perf_counter_ns(); signed=acct.sign_transaction(tx); sign=(time.perf_counter_ns()-t)/1e6
    t=time.perf_counter_ns(); txh=w3.eth.send_raw_transaction(signed.raw_transaction); submit=(time.perf_counter_ns()-t)/1e6
    t=time.perf_counter_ns(); rc=w3.eth.wait_for_transaction_receipt(txh,timeout=120); confirm=(time.perf_counter_ns()-t)/1e6
    return rc,sign,submit,confirm
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--workload",required=True); ap.add_argument("--domain",required=True)
    ap.add_argument("--output",required=True); ap.add_argument("--queries",type=int,default=5000); ap.add_argument("--warmup",type=int,default=500)
    ap.add_argument("--rpc",default=os.getenv("BESU_RPC_URL")); ap.add_argument("--artifact",default="build/DPKICommitmentRegistry.json"); args=ap.parse_args()
    if not args.rpc: raise SystemExit("BESU_RPC_URL or --rpc required")
    uk=os.getenv("BESU_PRIVATE_KEY"); vk=os.getenv("BESU_VALIDATOR_PRIVATE_KEY")
    if not uk or not vk: raise SystemExit("BESU_PRIVATE_KEY and BESU_VALIDATOR_PRIVATE_KEY required")
    wp=Path(args.workload); meta=json.loads((wp/"workload.json").read_text()); n=int(meta["n"])
    revoked={int(r["serial"]) for r in csv.DictReader((wp/"revoked_serials.csv").open())}
    rows=[(f"CERT-{s:08d}","REVOKED" if s in revoked else "VALID",s-1) for s in range(1,n+1)]
    out=Path(args.output); out.mkdir(parents=True,exist_ok=True); dbp=out/"directory.sqlite3"
    if dbp.exists(): dbp.unlink()
    db=sqlite3.connect(dbp); db.execute("CREATE TABLE certificate_status(cert_id TEXT PRIMARY KEY,status TEXT,leaf_index INTEGER)")
    db.executemany("INSERT INTO certificate_status VALUES(?,?,?)",rows); db.commit()
    t=time.perf_counter_ns(); leaves=[lh(r[0],r[1]) for r in rows]; leaf_ms=(time.perf_counter_ns()-t)/1e6
    t=time.perf_counter_ns(); tree=MT(leaves); tree_ms=(time.perf_counter_ns()-t)/1e6
    w3=Web3(Web3.HTTPProvider(args.rpc,request_kwargs={"timeout":120})); art=json.loads(Path(args.artifact).read_text())
    c=w3.eth.contract(address=Web3.to_checksum_address(art["address"]),abi=art["abi"])
    updater=w3.eth.account.from_key(uk); validator=w3.eth.account.from_key(vk); did=Web3.keccak(text=args.domain)
    e0=time.perf_counter_ns(); rc,ps,pu,pc=send(w3,c.functions.proposeCommitment(did,tree.root,n,len(revoked)),updater)
    if rc.status!=1: raise RuntimeError("proposal failed")
    vdb=sqlite3.connect(dbp); t=time.perf_counter_ns(); vr=vdb.execute("SELECT cert_id,status FROM certificate_status ORDER BY leaf_index").fetchall()
    vt=MT([lh(a,b) for a,b in vr]); recon=(time.perf_counter_ns()-t)/1e6; vdb.close(); match=vt.root==tree.root
    if not match: raise RuntimeError("C_D != C_V")
    rc2,vs,vu,vc=send(w3,c.functions.validateAndCommit(did,vt.root),validator)
    if rc2.status!=1: raise RuntimeError("validation failed")
    if bytes(c.functions.getCommitment(did).call()[0])!=tree.root: raise RuntimeError("anchored root mismatch")
    e2e=(time.perf_counter_ns()-e0)/1e6
    rng=random.Random(int(meta["seed"]))
    for _ in range(args.warmup):
        i=rng.randrange(n); assert verify(leaves[i],tree.proof(i),tree.root)
    q=[]
    for _ in range(args.queries):
        i=rng.randrange(n); t=time.perf_counter_ns(); p=tree.proof(i); pg=(time.perf_counter_ns()-t)/1e3
        t=time.perf_counter_ns(); root=bytes(c.functions.getCommitment(did).call()[0]); br=(time.perf_counter_ns()-t)/1e6
        t=time.perf_counter_ns(); ok=verify(leaves[i],p,root); pv=(time.perf_counter_ns()-t)/1e3
        if not ok: raise RuntimeError("proof failed")
        q.append((pg,br,pv,len(p)*32))
    init={"n":n,"revoked":len(revoked),"merkle_depth":tree.depth,"leaf_generation_ms":leaf_ms,"merkle_tree_build_ms":tree_ms,
          "besu_proposal_sign_ms":ps,"besu_proposal_submit_ms":pu,"besu_proposal_confirmation_ms":pc,
          "validator_commitment_reconstruction_ms":recon,"pre_anchor_root_match":int(match),
          "besu_validation_sign_ms":vs,"besu_validation_submit_ms":vu,"besu_validation_confirmation_ms":vc,
          "besu_proposal_gas_used":rc.gasUsed,"besu_validation_gas_used":rc2.gasUsed,"besu_block_number":rc2.blockNumber,"anchoring_e2e_ms":e2e}
    with (out/"initialization_metrics.csv").open("w",newline="") as f:
        w=csv.writer(f); w.writerow(["metric","value"]); w.writerows(init.items())
    with (out/"raw_verification_queries.csv").open("w",newline="") as f:
        w=csv.writer(f); w.writerow(["proof_generation_us","besu_root_read_ms","proof_verification_us","proof_sibling_bytes"]); w.writerows(q)
    db.close()
if __name__=="__main__": main()
