#!/usr/bin/env python3
# MiniScope – stylish recon by 0xyoussef404 

import argparse, asyncio, os, re, socket, subprocess, shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Set, Tuple
from collections import Counter, defaultdict
from urllib.parse import urlsplit

# ---------------- colors (safe fallback) ----------------
try:
    from colorama import Fore as C, Style as S, init as color_init
    color_init(autoreset=True)
except Exception:
    class _D:
        RESET_ALL=""; RED=""; BLUE=""; YELLOW=""; GREEN=""; CYAN=""; MAGENTA=""; WHITE=""
    C=_D(); S=_D()

# ---------------- banner----------------
BANNER = r"""
███╗   ███╗██╗███╗   ██╗██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
████╗ ████║██║████╗  ██║██║██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝
██╔████╔██║██║██╔██╗ ██║██║███████╗██║   ██║██████╔╝██║  ██║█████╗  
██║╚██╔╝██║██║██║╚██╗██║██║╚════██║██║   ██║██╔═══╝ ██║  ██║██╔══╝  
██║ ╚═╝ ██║██║██║ ╚████║██║███████║╚██████╔╝██║     ██████╔╝███████╗
╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝╚══════╝ ╚═════╝ ╚═╝     ╚═════╝ ╚══════╝
"""

# ---------------- utils ----------------
def now_utc() -> str:
    return datetime.utcnow().isoformat() + "Z"

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

async def run_cmd(cmd: List[str], **popen_kwargs) -> subprocess.CompletedProcess:
    return await asyncio.to_thread(
        subprocess.run, cmd, capture_output=True, text=True, **popen_kwargs
    )

def color_bool(ok: bool) -> str:
    return (C.GREEN + "✔" + S.RESET_ALL) if ok else (C.RED + "✘" + S.RESET_ALL)

def norm_host(h: str) -> str:
    h = (h or "").strip().lower()
    h = h.rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    return h

def resolve_one_ip(host: str) -> Optional[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        for _, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            return ip
    except Exception:
        return None

# ---------------- banner printer (kept look & checklist) ----------------
def print_banner(args, enabled_sources: List[str]):
    print(C.RED + BANNER + S.RESET_ALL)
    title = (
        C.YELLOW + "             [ "
        + C.BLUE + "MiniScope"
        + C.YELLOW + " :: recon tool by "
        + C.GREEN + "0xyoussef404"
        + C.YELLOW + " ]" + S.RESET_ALL
    )
    print(title + "\n")

    print(C.YELLOW + "------------------------------------------------------------" + S.RESET_ALL)
    print(f"{C.YELLOW}Sources:{S.RESET_ALL} " + C.BLUE + (", ".join(enabled_sources) or "none") + S.RESET_ALL)

    tools = {
        "subfinder": which("subfinder") is not None,
        "assetfinder": which("assetfinder") is not None,
        "amass": which("amass") is not None,
        "findomain": which("findomain") is not None,
        "katana": which("katana") is not None,
        "ping": which("ping") is not None,
        "dnsx": which("dnsx") is not None,
    }
    print(f"{C.YELLOW}Tools (local):{S.RESET_ALL}")
    for t, ok in tools.items():
        print(f"  - {t:<11} : {color_bool(ok)}")

    print(f"{C.YELLOW}Settings:{S.RESET_ALL}")
    print(f"  - Concurrency : {C.BLUE}{args.concurrency}{S.RESET_ALL}")
    print(f"  - HTTP timeout: {C.BLUE}{args.timeout}s{S.RESET_ALL}")
    print(f"  - Ping        : {C.BLUE}{'ON' if not args.no_ping else 'OFF'}{S.RESET_ALL}")
    if args.max_hosts:
        print(f"  - Cap hosts   : {C.BLUE}{args.max_hosts}{S.RESET_ALL}")
    if args.verify_dnsx:
        print(f"  - Verify dnsx : {C.BLUE}ON{S.RESET_ALL}")

    print(C.YELLOW + "------------------------------------------------------------\n" + S.RESET_ALL)
    tips = (
        f"{C.YELLOW}tips:{S.RESET_ALL} "
        f"--sources subfinder,assetfinder,amass,findomain,katana  |  "
        f"--no-ping  |  --concurrency 80  |  --timeout 6  |  --bruteforce  |  --debug-sources"
    )
    print(tips + "\n")

# ---------------- validation ----------------
SUB_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
def is_valid_subdomain(host: str, root: str) -> bool:
    host = norm_host(host)
    root = norm_host(root)
    if " " in host or "(" in host or ">" in host:
        return False
    if not SUB_RE.match(host):
        return False
    return host.endswith("." + root) or host == root

# ---------------- sources ----------------
async def subdomains_subfinder(domain: str, debug: bool) -> Set[str]:
    p = which("subfinder")
    if not p: return set()
    proc = await run_cmd([p, "-silent", "-all", "-nW", "-d", domain])
    if proc.returncode != 0:
        if debug: print(f"[subfinder:err] {proc.stderr.strip()}")
        return set()
    return { norm_host(ln) for ln in proc.stdout.splitlines() if ln.strip() }

async def subdomains_assetfinder(domain: str, debug: bool) -> Set[str]:
    p = which("assetfinder")
    if not p: return set()
    proc = await run_cmd([p, "--subs-only", domain])
    if proc.returncode != 0:
        if debug: print(f"[assetfinder:err] {proc.stderr.strip()}")
        return set()
    return { norm_host(ln) for ln in proc.stdout.splitlines() if ln.strip() }

async def subdomains_amass(domain: str, debug: bool) -> Set[str]:
    p = which("amass")
    if not p: return set()
    proc = await run_cmd([p, "enum", "-passive", "-d", domain, "-o", "-"])
    if proc.returncode != 0:
        if debug: print(f"[amass:err] {proc.stderr.strip()}")
        return set()
    return { norm_host(ln) for ln in proc.stdout.splitlines() if ln.strip() }

async def subdomains_findomain(domain: str, debug: bool) -> Set[str]:
    p = which("findomain")
    if not p: return set()
    proc = await run_cmd([p, "-t", domain, "-q"])
    if proc.returncode != 0:
        if debug: print(f"[findomain:err] {proc.stderr.strip()}")
        return set()
    return { norm_host(ln) for ln in proc.stdout.splitlines() if ln.strip() }

async def subdomains_katana(domain: str, debug: bool) -> Set[str]:
    """
    Run katana against https://domain and http://domain, collect URLs,
    extract netloc hostnames, keep hosts that end with the root domain.
    """
    p = which("katana")
    if not p: return set()

    targets = [f"https://{domain}", f"http://{domain}"]
    out_hosts: Set[str] = set()

    async def run_one(url: str):
        proc = await run_cmd([p, "-u", url, "-silent"])
        if proc.returncode != 0 and debug:
            print(f"[katana:err] {url} :: {proc.stderr.strip()}")
        for ln in proc.stdout.splitlines():
            ln = ln.strip()
            if not ln: continue
            try:
                netloc = urlsplit(ln).netloc
                host = norm_host(netloc.split(":")[0])  # strip port
                if is_valid_subdomain(host, domain):
                    out_hosts.add(host)
            except Exception:
                continue

    await asyncio.gather(*(run_one(u) for u in targets))
    return out_hosts

async def subdomains_bruteforce(domain: str, labels: List[str], debug: bool) -> Set[str]:
    if not labels: return set()
    out: Set[str] = set()
    sem = asyncio.Semaphore(100)
    async def try_one(lbl: str):
        sub = norm_host(f"{lbl}.{domain}")
        try:
            await asyncio.to_thread(socket.getaddrinfo, sub, None)
            out.add(sub)
        except Exception:
            pass
    await asyncio.gather(*(try_one(l) for l in labels))
    return out

async def gather_subdomains_with_sources(domain: str, enabled_sources: List[str], brute_labels: List[str], debug=False) -> Tuple[Dict[str, Set[str]], Dict[str, List[str]]]:
    tasks = []; names = []
    if "subfinder"   in enabled_sources: tasks.append(subdomains_subfinder(domain, debug));   names.append("subfinder")
    if "assetfinder" in enabled_sources: tasks.append(subdomains_assetfinder(domain, debug)); names.append("assetfinder")
    if "amass"       in enabled_sources: tasks.append(subdomains_amass(domain, debug));       names.append("amass")
    if "findomain"   in enabled_sources: tasks.append(subdomains_findomain(domain, debug));   names.append("findomain")
    if "katana"      in enabled_sources: tasks.append(subdomains_katana(domain, debug));      names.append("katana")
    if "bruteforce"  in enabled_sources: tasks.append(subdomains_bruteforce(domain, brute_labels, debug)); names.append("bruteforce")

    results = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []
    source_map: Dict[str, Set[str]] = {}
    samples: Dict[str, List[str]] = defaultdict(list)

    for src, subs in zip(names, results):
        if isinstance(subs, Exception):
            if debug: print(f"[debug] {src:<11} raised: {subs}")
            continue
        raw = 0
        kept = 0
        for sub in subs:
            raw += 1
            if not is_valid_subdomain(sub, domain):
                continue
            kept += 1
            source_map.setdefault(sub, set()).add(src)
            if debug and len(samples[src]) < 3:
                samples[src].append(sub)
        if debug:
            print(f"[debug] {src:<11} raw={raw:4d} kept={kept:4d}")

    source_map.setdefault(norm_host(domain), set()).add("manual-root")
    return source_map, samples

# ---------------- optional resolvable filter (dnsx) ----------------
async def filter_resolvable_with_dnsx(subs: List[str], debug: bool) -> List[str]:
    p = which("dnsx")
    if not p:
        if debug:
            print("[debug] dnsx not found; skipping verify step")
        return subs
    try:
        proc = await asyncio.to_thread(
            subprocess.run, [p, "-silent", "-a"],
            input="\n".join(subs), capture_output=True, text=True
        )
        if proc.returncode != 0 and debug:
            print(f"[dnsx:err] {proc.stderr.strip()}")
        good = set()
        for line in proc.stdout.splitlines():
            parts = line.split()
            if parts:
                good.add(norm_host(parts[0]))
        if debug:
            print(f"[debug] dnsx verified {len(good)}/{len(subs)}")
        return [s for s in subs if s in good] if good else subs
    except Exception as e:
        if debug:
            print(f"[dnsx:exc] {e}")
        return subs

# ---------------- probes ----------------
async def ping_host(host: str) -> Optional[bool]:
    p = which("ping")
    if not p: return None
    flag = "-c" if os.name != "nt" else "-n"
    try:
        proc = await run_cmd([p, flag, "1", host])
        return proc.returncode == 0
    except Exception:
        return None

async def http_probe(host: str, timeout: int, conn_limit: int) -> Dict[str, Optional[str]]:
    out = {"http_ok": False, "status": None, "final_url": None, "ip": None}
    out["ip"] = resolve_one_ip(host)
    try:
        import httpx
        limits = httpx.Limits(max_connections=conn_limit, max_keepalive_connections=conn_limit)
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, limits=limits, headers={"User-Agent":"MiniScope/1.0"}) as client:
            for scheme in ("https", "http"):
                try:
                    r = await client.get(f"{scheme}://{host}")
                    out["http_ok"] = True
                    out["status"] = str(r.status_code)
                    final_url = str(r.url)
                    if len(final_url) > 200:
                        final_url = final_url[:200] + "…"
                    out["final_url"] = final_url
                    break
                except Exception:
                    continue
    except Exception:
        pass
    return out

# ---------------- outputs ----------------
def safe_filename(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", text)

def write_markdown(path: Path, domain: str, rows: List[Dict[str, Optional[str]]], append: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append and path.exists() else "w"
    with path.open(mode, encoding="utf-8") as f:
        stamp = now_utc()
        f.write(f"# MiniScope Recon Report – {domain}\n\n")
        f.write(f"**Generated:** {stamp}\n\n")
        f.write("| Root Domain | Subdomain | IP | Ping | HTTP | Status | Final URL | Sources |\n")
        f.write("|-------------|-----------|----|------|------|--------|-----------|---------|\n")
        for r in rows:
            f.write(
                f"| {r['root_domain']} | {r['subdomain']} | {r.get('ip','') or ''} | "
                f"{r.get('ping_ok','')} | {r.get('http_ok','')} | {r.get('status','') or ''} | "
                f"{r.get('final_url','') or ''} | {r.get('source','') or ''} |\n"
            )
        f.write("\n")

def write_txt(path: Path, rows: List[Dict[str, Optional[str]]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    subs = sorted({ r["subdomain"] for r in rows if r.get("subdomain") })
    with path.open("w", encoding="utf-8") as f:
        for s in subs:
            f.write(f"{s}\n")

# ---------------- main domain flow ----------------
async def process_domain(domain: str, out_target: Path, treat_o_as_file: bool, append_to_file: bool, args):
    enabled_sources = [s.strip().lower() for s in args.sources.split(",")] if args.sources else ["subfinder","assetfinder","amass","findomain","katana"]
    if args.bruteforce and "bruteforce" not in enabled_sources:
        enabled_sources.append("bruteforce")
    brute_labels = ["www","api","dev","test","stage","staging","admin","portal","mail","cdn","img","static","app","beta","vpn","sso","auth"] if "bruteforce" in enabled_sources else []

    source_map, samples = await gather_subdomains_with_sources(domain, enabled_sources, brute_labels, debug=args.debug_sources)
    subs = sorted(source_map.keys())

    if args.max_hosts and len(subs) > args.max_hosts:
        subs = subs[:args.max_hosts]

    if args.verify_dnsx:
        subs = await filter_resolvable_with_dnsx(subs, debug=args.debug_sources)

    src_counts = Counter(s for ss in source_map.values() for s in ss)
    if src_counts:
        printable = ", ".join(f"{k}:{src_counts[k]}" for k in sorted(src_counts))
        print(f"[sources] {printable}")
    if args.debug_sources:
        for src, ex in samples.items():
            if ex:
                print(f"[debug] sample from {src}: " + ", ".join(ex))

    stamp = now_utc()
    rows: List[Dict[str, Optional[str]]] = []

    sem = asyncio.Semaphore(args.concurrency)
    async def worker(sub: str):
        async with sem:
            p = None if args.no_ping else await ping_host(sub)
            h = await http_probe(sub, timeout=args.timeout, conn_limit=args.concurrency)
            rows.append({
                "root_domain": norm_host(domain),
                "subdomain": norm_host(sub),
                "ip": h["ip"],
                "ping_ok": "" if p is None else str(bool(p)).upper(),
                "http_ok": str(bool(h["http_ok"])).upper(),
                "status": h["status"] or "",
                "final_url": h["final_url"] or "",
                "source": "+".join(sorted(source_map.get(sub, {"unknown"}))),
                "checked_at": stamp
            })

    await asyncio.gather(*(worker(s) for s in subs))

    # determine output paths (md + txt)
    if treat_o_as_file:
        md_file = out_target
        txt_file = out_target.with_suffix(".txt")
    else:
        base = safe_filename(domain)
        md_file = out_target / f"miniscope_{base}.md"
        txt_file = out_target / f"miniscope_{base}.txt"

    write_markdown(md_file, domain, rows, append=append_to_file)
    write_txt(txt_file, rows)

    print(f"[+] {domain}: {len(rows)} hosts -> {md_file}")
    print(f"[+] TXT list written -> {txt_file}")

# ---------------- args & entry ----------------
def parse_args():
    p = argparse.ArgumentParser(description="MiniScope – stylish recon by 0xyoussef404 (Markdown + TXT output)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-d","--domain", help="example.com")
    g.add_argument("-D","--domains-file", help="path with one root per line")
    p.add_argument("-o","--out", default="out", help="output .md file OR output directory (default: out)")
    p.add_argument("--append", action="store_true", help="append to existing MD if -o is a file")

    # speed controls
    p.add_argument("--concurrency", type=int, default=60, help="max concurrent probes (default 60)")
    p.add_argument("--timeout", type=int, default=8, help="HTTP timeout seconds (default 8)")
    p.add_argument("--no-ping", action="store_true", help="disable ping checks for speed")
    p.add_argument("--max-hosts", type=int, default=0, help="cap number of hosts to probe (0 = no cap)")

    # source controls
    p.add_argument("--sources", type=str, default="", help="comma list: subfinder,assetfinder,amass,findomain,katana")
    p.add_argument("--bruteforce", action="store_true", help="enable small DNS brute-force")

    # verify/filter
    p.add_argument("--verify-dnsx", action="store_true", help="filter to resolvable hosts using dnsx if available")

    # debug
    p.add_argument("--debug-sources", action="store_true", help="print per-source counts and samples")
    return p.parse_args()

async def amain():
    args = parse_args()
    out_arg = Path(args.out)
    treat_o_as_file = out_arg.suffix.lower() == ".md"

    enabled_sources = [s.strip().lower() for s in args.sources.split(",")] if args.sources else ["subfinder","assetfinder","amass","findomain","katana"]
    if args.bruteforce and "bruteforce" not in enabled_sources:
        enabled_sources.append("bruteforce")
    print_banner(args, enabled_sources)

    if args.domain:
        domains = [norm_host(args.domain.strip())]
    else:
        with open(args.domains_file, "r", encoding="utf-8") as f:
            domains = [norm_host(ln) for ln in f if ln.strip() and not ln.startswith("#")]

    for i, d in enumerate(domains):
        append_flag = args.append or (treat_o_as_file and i > 0)
        await process_domain(d, out_arg if treat_o_as_file else Path(args.out), treat_o_as_file, append_flag, args)

if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        print("[!] Interrupted")
