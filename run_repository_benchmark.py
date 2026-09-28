#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, gc, hashlib, json, math, platform, random, sqlite3, statistics, sys, time
from pathlib import Path

def h(x): return hashlib.sha256(x).digest()
def parent_hash(a,b): return h(b"\\x01"+a+b)
def leaf_hash(cert_id,status): return h(b"\\x00"+cert_id.encode()+b"|"+status.encode())

class MerkleTree:
    def __init__(self,leaves):
        self.levels=[leaves]; level=leaves
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
                sib=idx+1 if idx+1<len(level) else idx; out.append(("R",level[sib]))
            else: out.append(("L",level[idx-1]))
            idx//=2
        return out

def verify(leaf,proof,root):
    cur=leaf
    for side,sib in proof:
        cur=parent_hash(sib,cur) if side=="L" else parent_hash(cur,sib)
    return cur==root

def stats(xs):
    xs=[float(x) for x in xs]; n=len(xs); mean=statistics.fmean(xs)
    sd=statistics.stdev(xs) if n>1 else 0.0
    ci=1.96*sd/math.sqrt(n) if n>1 else 0.0
    return {"n_runs":n,"mean":mean,"sd":sd,"ci95_low":mean-ci,"ci95_high":mean+ci,
            "min":min(xs),"max":max(xs)}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--workload",required=True)
    ap.add_argument("--repeats",type=int,default=10)
    ap.add_argument("--queries",type=int,default=5000)
    ap.add_argument("--warmup",type=int,default=500)
    ap.add_argument("--output",default="results_repository")
    args=ap.parse_args()
    wp=Path(args.workload)
    meta=json.loads((wp/"workload.json").read_text())
    revoked={int(r["serial"]) for r in csv.DictReader((wp/"revoked_serials.csv").open())}
    n=int(meta["n"]); out=Path(args.output); out.mkdir(parents=True,exist_ok=True)
    run_rows=[]; query_rows=[]
    for rep in range(1,args.repeats+1):
        rows=[(f"CERT-{i:08d}","REVOKED" if i in revoked else "VALID",i-1) for i in range(1,n+1)]
        db=sqlite3.connect(":memory:")
        db.execute("CREATE TABLE certificate_status(cert_id TEXT PRIMARY KEY,status TEXT,leaf_index INTEGER)")
        db.executemany("INSERT INTO certificate_status VALUES(?,?,?)",rows); db.commit()
        gc.collect(); was_gc=gc.isenabled()
        if was_gc: gc.disable()
        try:
            t=time.perf_counter_ns(); leaves=[leaf_hash(cid,status) for cid,status,_ in rows]
            leaf_ms=(time.perf_counter_ns()-t)/1e6
            t=time.perf_counter_ns(); tree=MerkleTree(leaves)
            tree_ms=(time.perf_counter_ns()-t)/1e6
        finally:
            if was_gc: gc.enable()
        rng=random.Random(int(meta["seed"])+rep)
        for _ in range(args.warmup):
            idx=rng.randrange(n); p=tree.proof(idx); assert verify(leaves[idx],p,tree.root)
        proof_gen=[]; proof_verify=[]; proof_bytes=[]
        for _ in range(args.queries):
            idx=rng.randrange(n)
            t=time.perf_counter_ns(); p=tree.proof(idx); proof_gen.append((time.perf_counter_ns()-t)/1e3)
            t=time.perf_counter_ns(); ok=verify(leaves[idx],p,tree.root); proof_verify.append((time.perf_counter_ns()-t)/1e3)
            if not ok: raise RuntimeError("proof verification failed")
            proof_bytes.append(len(p)*32)
        run_rows.append({"repeat":rep,"n":n,"revoke_ratio":meta["revoke_ratio"],
          "revoked_count":len(revoked),"merkle_depth":tree.depth,"leaf_generation_ms":leaf_ms,
          "merkle_tree_build_ms":tree_ms,"commitment_generation_ms":leaf_ms+tree_ms,
          "proof_generation_mean_us":statistics.fmean(proof_gen),
          "proof_verification_mean_us":statistics.fmean(proof_verify),
          "proof_sibling_bytes":proof_bytes[0]})
        query_rows.extend({"repeat":rep,"proof_generation_us":g,"proof_verification_us":v}
                          for g,v in zip(proof_gen,proof_verify))
        db.close()
        print(f"rep {rep}: commitment={leaf_ms+tree_ms:.3f} ms, depth={tree.depth}")
    with (out/"raw_repository_runs.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=run_rows[0].keys()); w.writeheader(); w.writerows(run_rows)
    with (out/"raw_repository_queries.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=query_rows[0].keys()); w.writeheader(); w.writerows(query_rows)
    metrics=["leaf_generation_ms","merkle_tree_build_ms","commitment_generation_ms",
             "proof_generation_mean_us","proof_verification_mean_us","proof_sibling_bytes"]
    summary=[]
    for m in metrics:
        summary.append({"metric":m,**stats([r[m] for r in run_rows])})
    with (out/"summary_repository.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=summary[0].keys()); w.writeheader(); w.writerows(summary)
    env={"python":sys.version.replace("\n"," "),"platform":platform.platform(),"workload":meta,
         "repeats":args.repeats,"queries_per_run":args.queries,"warmup_per_run":args.warmup,
         "blockchain":"not used in repository-scale benchmark"}
    (out/"environment_repository.json").write_text(json.dumps(env,indent=2),encoding="utf-8")

if __name__=="__main__":
    main()
