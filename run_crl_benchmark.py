#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, gc, json, math, statistics, time, platform, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

def percentile(xs, p):
    s = sorted(xs)
    idx = max(0, min(len(s)-1, math.ceil(p*len(s))-1))
    return s[idx]

def stats(xs):
    xs=[float(x) for x in xs]
    n=len(xs); mean=statistics.fmean(xs)
    sd=statistics.stdev(xs) if n>1 else 0.0
    ci=1.96*sd/math.sqrt(n) if n>1 else 0.0
    return {"n_runs":n,"mean":mean,"sd":sd,"ci95_low":mean-ci,"ci95_high":mean+ci,
            "median":statistics.median(xs),"p95":percentile(xs,.95),"min":min(xs),"max":max(xs)}

def create_ca():
    key=ec.generate_private_key(ec.SECP256R1())
    subject=x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,"KR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,"DPKI Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME,"D01-A Root CA")])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
          .sign(key,hashes.SHA256()))
    return key,cert

def load_revoked(path):
    with Path(path).open(newline="",encoding="utf-8") as f:
        return [int(r["serial"]) for r in csv.DictReader(f)]

def build_crl(ca_key,ca_cert,serials):
    now=datetime.now(timezone.utc)
    b=(x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject)
       .last_update(now).next_update(now+timedelta(days=7)))
    for serial in serials:
        b=b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build())
    return b.sign(private_key=ca_key,algorithm=hashes.SHA256())

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--workload",required=True)
    ap.add_argument("--repeats",type=int,default=10)
    ap.add_argument("--output",default="results_crl")
    args=ap.parse_args()
    out=Path(args.output); out.mkdir(parents=True,exist_ok=True)
    serials=load_revoked(Path(args.workload)/"revoked_serials.csv")
    meta=json.loads((Path(args.workload)/"workload.json").read_text())
    ca_key,ca_cert=create_ca()
    rows=[]
    for rep in range(1,args.repeats+1):
        gc.collect(); was_gc=gc.isenabled()
        if was_gc: gc.disable()
        try:
            t0=time.perf_counter_ns(); crl=build_crl(ca_key,ca_cert,serials)
            generation_ms=(time.perf_counter_ns()-t0)/1e6
            t0=time.perf_counter_ns(); der=crl.public_bytes(serialization.Encoding.DER)
            serialization_ms=(time.perf_counter_ns()-t0)/1e6
            t0=time.perf_counter_ns(); parsed=x509.load_der_x509_crl(der)
            parse_ms=(time.perf_counter_ns()-t0)/1e6
            t0=time.perf_counter_ns(); sig_ok=parsed.is_signature_valid(ca_cert.public_key())
            verify_ms=(time.perf_counter_ns()-t0)/1e6
        finally:
            if was_gc: gc.enable()
        rows.append({"repeat":rep,"n":meta["n"],"revoke_ratio":meta["revoke_ratio"],
          "revoked_count":len(serials),"crl_generation_ms":generation_ms,
          "crl_serialization_ms":serialization_ms,"crl_parse_ms":parse_ms,
          "crl_signature_verify_ms":verify_ms,"crl_der_bytes":len(der),"signature_valid":sig_ok})
        print(f"rep {rep}: generation={generation_ms:.3f} ms, size={len(der):,} B")
    with (out/"raw_crl_benchmark.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    metrics=["crl_generation_ms","crl_serialization_ms","crl_parse_ms",
             "crl_signature_verify_ms","crl_der_bytes"]
    summary=[]
    for m in metrics:
        s=stats([r[m] for r in rows]); s={"metric":m,**s}; summary.append(s)
    with (out/"summary_crl_benchmark.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=summary[0].keys()); w.writeheader(); w.writerows(summary)
    env={"python":sys.version.replace("\n"," "),"platform":platform.platform(),
         "workload":meta,"repeats":args.repeats,"gc_disabled_during_measurement":True}
    (out/"environment_crl.json").write_text(json.dumps(env,indent=2),encoding="utf-8")

if __name__=="__main__":
    main()
