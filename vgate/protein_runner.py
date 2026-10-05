#!/usr/bin/env python3
"""vgate compute-family runner for real protein-multimer prediction (AlphaFold2-multimer via colabfold).

Turns a binder -> target ipTM prediction into a single machine-parseable line so vgate's
compute family can gate on it. Reuses the real colabfold_batch invocation (same flags as
multimer_screen.py), with a --dry-run mode that emits a mock log so the vgate gate logic
can be validated on machines where the GPU is busy (or never present).

Usage:
  protein_runner.py <binders.fa> <target.fa> <outdir> [--dry-run [--fake-iptm 0.63]]
Output line (stdout, always parseable):
  RESULT name=<id> len=<n> ipTM=<float|NA> pLDDT=<float|NA> pTM=<float|NA> exit=<code|timeout|dryrun>

Gate semantics: vgate spec asks ipTM >= threshold (statistical). This runner never claims
binding — it reports a predicted metric. Wet-lab is out of scope, stated via ceiling.
"""
import re, os, sys, json, glob, subprocess, argparse

CF = "/mnt/i/hermes/protein-design/venv/bin/colabfold_batch"


def read_target(fa):
    t = None
    for ln in open(fa):
        ln = ln.strip()
        if ln.startswith(">") or not ln:
            continue
        t = ln
        break
    if not t:
        sys.exit("ERROR: no target seq in %s" % fa)
    return t


def read_binders(fa):
    binders = []
    cur = None
    for ln in open(fa):
        ln = ln.strip()
        if ln.startswith(">"):
            cur = ln[1:].split()[0]
        elif cur is not None and ln:
            binders.append((cur, ln))
            cur = None
    return binders


def parse_ipTM(log_text, outd):
    """rank_001 line, else scores_rank_001 json, else log.txt, else None."""
    m = re.search(r"rank_001.*pLDDT=([\d.]+)\s+pTM=([\d.]+)\s+ipTM=([\d.]+)", log_text)
    if m:
        return float(m.group(3)), float(m.group(1)), float(m.group(2))
    for sj in sorted(glob.glob(os.path.join(outd, "*scores_rank_001*.json"))):
        try:
            sd = json.load(open(sj))
            pl = sd.get("plddt", [])
            return float(sd["iptm"]), (sum(pl)/len(pl)) if pl else None, sd.get("ptm")
        except Exception:
            continue
    lf = os.path.join(outd, "log.txt")
    if os.path.exists(lf):
        mm = re.search(r"rank_001.*pLDDT=([\d.]+)\s+pTM=([\d.]+)\s+ipTM=([\d.]+)", open(lf).read())
        if mm:
            return float(mm.group(3)), float(mm.group(1)), float(mm.group(2))
    return None, None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binders_fa")
    ap.add_argument("target_fa")
    ap.add_argument("outdir")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--fake-iptm", type=float, default=0.63)
    ap.add_argument("--model", default="alphafold2_multimer_v3")
    ap.add_argument("--num-models", type=int, default=1)
    a = ap.parse_args()

    tseq = read_target(a.target_fa)
    binders = read_binders(a.binders_fa)
    os.makedirs(a.outdir, exist_ok=True)

    for name, seq in binders:
        fa = os.path.join(a.outdir, "_%s.fa" % name)
        with open(fa, "w") as f:
            f.write(">%s\n%s:%s\n" % (name, tseq, seq))
        od = os.path.join(a.outdir, name)
        os.makedirs(od, exist_ok=True)

        if a.dry_run:  # no GPU needed: emit a plausible rank_001 line the real tool would
            log = "rank_001 1.23 0.456 pLDDT=88.4 pTM=0.721 ipTM=%0.3f" % a.fake_iptm
            iptm, plddt, ptm = parse_ipTM(log, od)
            print("RESULT name=%s len=%d ipTM=%s pLDDT=%s pTM=%s exit=dryrun"
                  % (name, len(seq), iptm, plddt, ptm))
            continue

        try:
            r = subprocess.run(
                [CF, "--msa-mode", "single_sequence", "--num-recycle", "3",
                 "--num-models", str(a.num_models), "--model-type", a.model,
                 "--rank", "iptm", "--disable-unified-memory", "--recompile-padding", "32",
                 fa, od], capture_output=True, text=True, timeout=300)
            log = r.stdout + r.stderr
            iptm, plddt, ptm = parse_ipTM(log, od)
            print("RESULT name=%s len=%d ipTM=%s pLDDT=%s pTM=%s exit=%s"
                  % (name, len(seq), iptm, plddt, ptm, r.returncode))
        except subprocess.TimeoutExpired:
            print("RESULT name=%s len=%d ipTM=NA pLDDT=NA pTM=NA exit=timeout" % (name, len(seq)))


if __name__ == "__main__":
    main()