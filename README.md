# MiniScope 🔍

**MiniScope** is a lightweight and fast recon tool that aggregates multiple sources to discover subdomains in one step, generating a **Markdown report** ready for GitHub.
Built to streamline the initial phase of any Pentest or Bug Bounty.

```
███╗   ███╗██╗███╗   ██╗██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
████╗ ████║██║████╗  ██║██║██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔════╝
██╔████╔██║██║██╔██╗ ██║██║███████╗██║   ██║██████╔╝██║  ██║█████╗  
██║╚██╔╝██║██║██║╚██╗██║██║╚════██║██║   ██║██╔═══╝ ██║  ██║██╔══╝  
██║ ╚═╝ ██║██║██║ ╚████║██║███████║╚██████╔╝██║     ██████╔╝███████╗
╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝╚══════╝ ╚═════╝ ╚═╝     ╚═════╝ ╚══════╝
                    [ MiniScope :: by 0xyoussef404 ]
```

---

## ✨ Features

* Aggregates multiple subdomain discovery sources:

  * **subfinder**, **assetfinder**, **amass**, **findomain**, **dnsx**, and **crt.sh** (HTTP).
  * Choose subset with `--sources`.
* **One Markdown report** neatly formatted for GitHub.
* **Colored banner** in terminal + tool/source status.
* **Performance control**: `--concurrency`, `--timeout`, `--no-ping`.
* **Optional bruteforce** with common labels: `--bruteforce`.
* **Debug per-source**: count + sample via `--debug-sources`.
* **Cross-platform** (Linux, Windows, macOS).

---

## 📁 Output Structure

* Results saved in:

  * **One Markdown file per domain** inside a folder defined with `-o`, or single file if `-o` is a `.md` file.
* Example output file:

  ```
  out/miniscope_example_com.md
  ```

---

## 🧰 Requirements

### Python

* **Python 3.9+** recommended.
* Dependencies (in `requirements.txt`):

  * `httpx`
  * `colorama`

> Setup virtual environment (optional but recommended):

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# or Linux/macOS
source .venv/bin/activate
```

> Install requirements:

```bash
pip install -r requirements.txt
```

### External Tools (recommended)

Must be in **PATH** if you want them:

* [subfinder](https://github.com/projectdiscovery/subfinder)
* [assetfinder](https://github.com/tomnomnom/assetfinder)
* [amass](https://github.com/owasp-amass/amass)
* [findomain](https://github.com/findomain/findomain)
* [dnsx](https://github.com/projectdiscovery/dnsx)

#### Linux (Kali/Debian)

```bash
sudo apt update && sudo apt install -y subfinder amass
# assetfinder (manual):
go install github.com/tomnomnom/assetfinder@latest
# findomain (binary):
wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip && sudo mv findomain /usr/local/bin/
# dnsx (go install):
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

#### Windows (via Scoop)

```powershell
scoop install git
scoop install subfinder
scoop install amass
# assetfinder & findomain usually manual (download binary → put in %USERPROFILE%\scoop\shims)
$env:PATH += ";$env:USERPROFILE\scoop\shims"
```

> If any tool is missing, MiniScope continues gracefully with available sources.

---

## ⚡ Quick Usage

### Single domain ➜ save in folder

```bash
python miniscope.py -d example.com -o out
```

### Multiple domains from file ➜ write to one file with `--append`

```bash
python miniscope.py -D domains.txt -o all_results.md --append
```

### Faster scan + no ping

```bash
python miniscope.py -d example.com -o out --concurrency 100 --timeout 6 --no-ping
```

### Select sources

```bash
python miniscope.py -d example.com -o out --sources subfinder,crtsh,dnsx
```

### Enable bruteforce

```bash
python miniscope.py -d example.com -o out --bruteforce
```

### Debug sources (count + samples)

```bash
python miniscope.py -d example.com -o out --debug-sources
```

---

## 🔧 CLI Options

| Option               | Description                                                    |
| -------------------- | -------------------------------------------------------------- |
| `-d, --domain`       | Single domain (e.g., `example.com`)                            |
| `-D, --domains-file` | File with domains (one per line)                               |
| `-o, --out`          | Output folder or single `.md` file                             |
| `--append`           | When output is a single file, append instead of overwrite      |
| `--concurrency`      | Concurrency level (default 60)                                 |
| `--timeout`          | HTTP timeout in seconds (default 8)                            |
| `--no-ping`          | Disable ping check                                             |
| `--max-hosts`        | Max hosts (0 = unlimited)                                      |
| `--sources`          | Comma list: `subfinder,crtsh,assetfinder,amass,findomain,dnsx` |
| `--bruteforce`       | Enable small bruteforce list (www, api, dev, …)                |
| `--debug-sources`    | Print per-source stats and samples                             |

---

## 📝 Example `domains.txt`

```
example.com
dust.tt
testphp.vulnweb.com
```

---

## 📂 Example Markdown Output

```markdown
# MiniScope Recon Report – example.com

**Generated:** 2025-08-19T12:34:56Z

| Root Domain | Subdomain        | IP            | Ping | HTTP | Status | Final URL                 | Sources               |
|-------------|------------------|---------------|------|------|--------|---------------------------|-----------------------|
| example.com | www.example.com  | 93.184.216.34 | TRUE | TRUE | 200    | https://www.example.com   | subfinder+crt.sh      |
| example.com | api.example.com  | 203.0.113.10  |      | TRUE | 403    | http://api.example.com    | assetfinder+dnsx      |
```

---

## 🛠️ Troubleshooting

**1) Tool not recognized in VS Code/PyCharm**
Run in same terminal you installed or add PATH manually:

```powershell
$env:PATH += ";$env:USERPROFILE\scoop\shims"
where subfinder
where amass
where assetfinder
```

**2) amass returns nothing**
Expected in `-passive` without API keys.
Enhance via `~/.config/amass/config.ini` with Shodan/Censys/etc.

**3) crt.sh down?**
If temporarily unavailable, retry later or rely on other sources.

---

## 📥 Quick Install

```bash
git clone https://github.com/0xyoussef404/miniscope.git
cd miniscope
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
python miniscope.py -d example.com -o out
```

---

## 📜 License

MIT — free to use, modify, and distribute. Please credit the author 🙏

---

## 👨‍💻 Author

**0xyoussef404** — PRs and issues welcome!
