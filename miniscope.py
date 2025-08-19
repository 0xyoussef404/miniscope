#!/usr/bin/env python3
import argparse, asyncio, os, re, socket, subprocess, shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Set, Tuple
from collections import Counter, defaultdict
import httpx

# ------------ colors (banner + info) ------------
try:
    from colorama import Fore, Style, init as color_init
    color_init(autoreset=True)
    C = Fore  # shorthand
    S = Style
except Exception:
    class _D: RESET_ALL=""; RED=""; BLUE=""; YELLOW=""; GREEN=""; CYAN=""; MAGENTA=""; WHITE=""; LIGHTBLACK_EX=""; BRIGHT=""
    C = _D(); S=_D()

# ------------ constants / utils ------------
CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

async def run_cmd(cmd: list) -> subprocess.CompletedProcess:
    return await asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True)

def safe_filename(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", text)

def now_utc() -> str:
    return datetime.utcnow().isoformat() + "Z"

# ------------ validation ------------
SUB_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
def is_valid_subdomain(host: str, root: str) -> bool:
    host = host.strip().lower()
    if " " in host or "(" in host or ">" in host:
        return False
    if not SUB_RE.match(host):
        return False
    return host.endswith("." + root) or host == root

# ------------ health / banner helpers ------------
def check_crtsh_alive(timeout=5) -> bool:
    try:
        r = httpx.get("https://crt.sh/", timeout=timeout)
        return r.status_code < 500
    except Exception:
        return False

def color_bool(ok: bool) -> str:
    return (C.GREEN + "✔" + S.RESET_ALL) if ok else (C.RED + "✘" + S.RESET_ALL)

BANNER_TEXT = r"""
███╗   ███╗██╗███╗   ██╗██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
████╗ ████║██║████╗  ██║██║██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝
██╔████╔██║██║██╔██╗ ██║██║███████╗██║   ██║██████╔╝██║  ██║█████╗  
██║╚██╔╝██║██║██║╚██╗██║██║╚════██║██║   ██║██╔═══╝ ██║  ██║██╔══╝  
██║ ╚═╝ ██║██║██║ ╚████║██║███████║╚██████╔╝██║     ██████╔╝███████╗
╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝╚══════╝ ╚═════╝ ╚═╝     ╚═════╝ ╚══════╝
"""

def print_banner(args, enabled_sources: List[str]):
    # big logo: RED
    print(C.RED + BANNER_TEXT + S.RESET_ALL)
    # title: MiniScope BLUE, your name GREEN, brackets/details YELLOW
    title = (
        C.YELLOW + "             [ "
        + C.BLUE + "MiniScope"
        + C.YELLOW + " :: recon tool by "
        + C.GREEN + "0xyoussef404"
        + C.YELLOW + " ]" + S.RESET_ALL
    )
    print(title + "\n")

    # local tools detection
    tools = {
        "subfinder": which("subfinder") is not None,
        "assetfinder": which("assetfinder") is not None,
        "amass": which("amass") is not None,
        "ping": which("ping") is not None,
    }

    print(C.YELLOW + "------------------------------------------------------------" + S.RESET_ALL)
    print(f"{C.YELLOW}Sources:{S.RESET_ALL} " + C.BLUE + (", ".join(enabled_sources) or "none") + S.RESET_ALL)

    # online sources health (only crt.sh now)
    if "crtsh" in [s.replace(".", "") for s in enabled_sources] or "crt.sh" in enabled_sources:
        print(f"{C.YELLOW}Online sources:{S.RESET_ALL}")
        print(f"  - crt.sh      : {color_bool(check_crtsh_alive())}")

    print(f"{C.YELLOW}Tools (local):{S.RESET_ALL}")
    for t, ok in tools.items():
        print(f"  - {t:<11} : {color_bool(ok)}")

    print(f"{C.YELLOW}Settings:{S.RESET_ALL}")
    print(f"  - Concurrency : {C.BLUE}{args.concurrency}{S.RESET_ALL}")
    print(f"  - HTTP timeout: {C.BLUE}{args.timeout}s{S.RESET_ALL}")
    print(f"  - Ping        : {C.BLUE}{'ON' if not args.no_ping else 'OFF'}{S.RESET_ALL}")
    if args.max_hosts:
        print(f"  - Cap hosts   : {C.BLUE}{args.max_hosts}{S.RESET_ALL}")

    print(C.YELLOW + "------------------------------------------------------------\n" + S.RESET_ALL)
    tips = (
        f"{C.YELLOW}tips:{S.RESET_ALL} "
        f"--sources subfinder,assetfinder,amass,crtsh  |  "
        f"--no-ping  |  --concurrency 80  |  --timeout 6  |  --bruteforce  |  --debug-sources"
    )
    print(tips + "\n")

# ------------ subdomain sources ------------
async def subdomains_subfinder(domain: str) -> Set[str]:
    path = which("subfinder")
    if not path: return set()
    proc = await run_cmd([path, "-silent", "-d", domain])
    if proc.returncode != 0: return set()
    return {ln.strip().lower() for ln in proc.stdout.splitlines() if ln.strip()}

async def subdomains_crtsh(domain: str) -> Set[str]:
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(CRT_URL.format(domain=domain), headers={"User-Agent":"MiniScope/1.0"})
            if r.status_code != 200: return set()
            names = set()
            for item in r.json():
                for n in str(item.get("name_value","")).split("\n"):
                    n = n.strip().lower()
                    if n.endswith("." + domain) or n == domain:
                        names.add(n)
            return names
    except Exception:
        return set()

async def subdomains_assetfinder(domain: str) -> Set[str]:
    path = which("assetfinder")
    if not path: return set()
    proc = await run_cmd([path, "--subs-only", domain])
    if proc.returncode != 0: return set()
    return {ln.strip().lower() for ln in proc.stdout.splitlines() if ln.strip()}

async def subdomains_amass(domain: str) -> Set[str]:
    path = which("amass")
    if not path: return set()
    # -o - => pure hostnames (no graph). Note: passive without config may be sparse.
    proc = await run_cmd([path, "enum", "-passive", "-d", domain, "-o", "-"])
    if proc.returncode != 0: return set()
    return {ln.strip().lower() for ln in proc.stdout.splitlines() if ln.strip()}

async def subdomains_bruteforce(domain: str, labels: List[str]) -> Set[str]:
    if not labels: return set()
    out = set()
    sem = asyncio.Semaphore(100)
    async def try_one(lbl: str):
        sub = f"{lbl}.{domain}"
        try:
            await asyncio.to_thread(socket.gethostbyname, sub)
            out.add(sub)
        except Exception:
            pass
    await asyncio.gather(*(try_one(l) for l in labels))
    return out

async def gather_subdomains_with_sources(domain: str, enabled_sources: List[str], brute_labels: List[str], debug=False) -> Tuple[Dict[str, Set[str]], Dict[str, List[str]]]:
    """returns: source_map, samples_per_source (for debug)"""
    tasks = []; names = []
    if "subfinder"   in enabled_sources: tasks.append(subdomains_subfinder(domain));   names.append("subfinder")
    if "crtsh"       in enabled_sources: tasks.append(subdomains_crtsh(domain));       names.append("crt.sh")
    if "assetfinder" in enabled_sources: tasks.append(subdomains_assetfinder(domain)); names.append("assetfinder")
    if "amass"       in enabled_sources: tasks.append(subdomains_amass(domain));       names.append("amass")
    if "bruteforce"  in enabled_sources: tasks.append(subdomains_bruteforce(domain, brute_labels)); names.append("bruteforce")

    results = await asyncio.gather(*tasks) if tasks else []
    source_map: Dict[str, Set[str]] = {}
    samples: Dict[str, List[str]] = defaultdict(list)

    for src, subs in zip(names, results):
        count_before = 0
        for sub in subs:
            if not is_valid_subdomain(sub, domain):
                continue
            source_map.setdefault(sub, set()).add(src)
            if debug and len(samples[src]) < 3:
                samples[src].append(sub)
            count_before += 1
        if debug:
            print(f"{C.YELLOW}[debug]{S.RESET_ALL} source '{src}' returned {C.BLUE}{count_before}{S.RESET_ALL} lines (raw)")

    # always include root for probe
    source_map.setdefault(domain, set()).add("manual-root")
    return source_map, samples

# ------------ probes ------------
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
    try:
        out["ip"] = socket.gethostbyname(host)
    except Exception:
        out["ip"] = None

    limits = httpx.Limits(max_connections=conn_limit, max_keepalive_connections=conn_limit)
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, limits=limits) as client:
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
    return out

# ------------ markdown output ------------
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

# ------------ main flow ------------
async def process_domain(domain: str, out_target: Path, treat_o_as_file: bool, append_to_file: bool, args):
    # enabled sources
    enabled_sources = [s.strip().lower() for s in args.sources.split(",")] if args.sources else ["subfinder","crtsh","assetfinder","amass"]
    if args.bruteforce and "bruteforce" not in enabled_sources:
        enabled_sources.append("bruteforce")

    # banner once
    if args._print_banner_once:
        print_banner(args, enabled_sources)
        args._print_banner_once = False

    brute_labels = ["www","api","dev","test","stage","staging","admin","portal","mail","cdn","img","static","app","beta","vpn","sso","auth"] if "bruteforce" in enabled_sources else []

    source_map, samples = await gather_subdomains_with_sources(domain, enabled_sources, brute_labels, debug=args.debug_sources)
    subs = sorted(source_map.keys())

    # cap if requested
    if args.max_hosts and len(subs) > args.max_hosts:
        subs = subs[:args.max_hosts]

    # counts per source
    src_counts = Counter(s for ss in source_map.values() for s in ss)
    if src_counts:
        printable = {k: src_counts[k] for k in sorted(src_counts)}
        print(f"[sources] {printable}")
    # show samples if debugging
    if args.debug_sources:
        for src, ex in samples.items():
            if ex:
                print(f"{C.YELLOW}[debug]{S.RESET_ALL} sample from {src}: " + ", ".join(ex))

    stamp = now_utc()
    rows: List[Dict[str, Optional[str]]] = []

    sem = asyncio.Semaphore(args.concurrency)
    async def worker(sub: str):
        async with sem:
            p = None if args.no_ping else await ping_host(sub)
            h = await http_probe(sub, timeout=args.timeout, conn_limit=args.concurrency)
            rows.append({
                "root_domain": domain,
                "subdomain": sub,
                "ip": h["ip"],
                "ping_ok": "" if p is None else str(bool(p)).upper(),
                "http_ok": str(bool(h["http_ok"])).upper(),
                "status": h["status"] or "",
                "final_url": h["final_url"] or "",
                "source": "+".join(sorted(source_map.get(sub, {"unknown"}))),
                "checked_at": stamp
            })

    await asyncio.gather(*(worker(s) for s in subs))

    if treat_o_as_file:
        out_file = out_target
    else:
        base = safe_filename(domain)
        out_file = out_target / f"miniscope_{base}.md"

    write_markdown(out_file, domain, rows, append=append_to_file)
    print(f"[+] {domain}: {len(rows)} hosts -> {out_file}")

def parse_args():
    p = argparse.ArgumentParser(description="MiniScope – stylish recon by 0xyoussef404 (Markdown output)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-d","--domain", help="example.com")
    g.add_argument("-D","--domains-file", help="path with one root per line")
    p.add_argument("-o","--out", default="out", help="output .md file OR output directory")
    p.add_argument("--append", action="store_true", help="append to existing MD if -o is a file")

    # speed controls
    p.add_argument("--concurrency", type=int, default=60, help="max concurrent probes (default 60)")
    p.add_argument("--timeout", type=int, default=8, help="HTTP timeout seconds (default 8)")
    p.add_argument("--no-ping", action="store_true", help="disable ping checks for speed")
    p.add_argument("--max-hosts", type=int, default=0, help="cap number of hosts to probe (0 = no cap)")

    # source controls
    p.add_argument("--sources", type=str, default="", help="comma list: subfinder,crtsh,assetfinder,amass")
    p.add_argument("--bruteforce", action="store_true", help="enable small DNS brute-force")

    # debug
    p.add_argument("--debug-sources", action="store_true", help="print per-source counts and samples")

    args = p.parse_args()
    args._print_banner_once = True
    return args

async def amain():
    args = parse_args()
    out_arg = Path(args.out)
    treat_o_as_file = out_arg.suffix.lower() == ".md"

    if args.domain:
        domains = [args.domain.strip()]
    else:
        with open(args.domains_file, "r", encoding="utf-8") as f:
            domains = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    for i, d in enumerate(domains):
        append_flag = args.append or (treat_o_as_file and i > 0)
        await process_domain(d, out_arg if treat_o_as_file else Path(args.out), treat_o_as_file, append_flag, args)

if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        print("[!] Interrupted")
