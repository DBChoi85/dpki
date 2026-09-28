#!/usr/bin/env python3
import argparse,os,subprocess,sys
from pathlib import Path
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--repeats",type=int,default=10); ap.add_argument("--queries",type=int,default=5000)
    ap.add_argument("--warmup",type=int,default=500); ap.add_argument("--output",default="results/besu_scale")
    ap.add_argument("--rpc",default=os.getenv("BESU_RPC_URL")); ap.add_argument("--artifact",default="build/DPKICommitmentRegistry.json"); args=ap.parse_args()
    if not args.rpc: raise SystemExit("Besu RPC required: use --rpc or set BESU_RPC_URL")
    for n in (100,1000,10000,100000):
        workload=f"workload_{n}"
        if not Path(workload).exists(): raise SystemExit(f"Missing {workload}")
        print(f"\n{'='*64}\nRepository scale N={n:,}\n{'='*64}",flush=True)
        cmd=[sys.executable,"run_besu_repeated_benchmark.py","--workload",workload,"--repeats",str(args.repeats),
             "--queries",str(args.queries),"--warmup",str(args.warmup),"--domain-prefix",f"DPKI-{n}",
             "--output",f"{args.output}/n_{n}","--artifact",args.artifact]
        if args.rpc: cmd += ["--rpc",args.rpc]
        if subprocess.run(cmd).returncode!=0: raise SystemExit(f"N={n} failed")
    print("\nAll repository scales completed.",flush=True)
if __name__=="__main__": main()
