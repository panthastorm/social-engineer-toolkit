#!/usr/bin/env python3
# coding=utf-8
#
# osint_recon.py - OSINT / reconnaissance orchestrator for authorized engagements
#
# Drives the standard Kali Linux reconnaissance tool-chain against a target you
# are AUTHORIZED to test, collects the output into a tidy, timestamped
# engagement folder, and writes a summary report.
#
# Passive gathering runs by default. Anything that actively touches the target
# (port scans, web fuzzing, brute-forced DNS) only runs when you pass --active,
# so you never accidentally throw traffic at a host you did not mean to.
#
# This tool orchestrates other tools; it does not exploit anything. Use it only
# against systems you own or have explicit written permission to assess.

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


class C:
    """ANSI colours (no dependency on a colour library)."""
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


def info(msg):
    print("{0}[*]{1} {2}".format(C.B, C.END, msg))


def ok(msg):
    print("{0}[+]{1} {2}".format(C.G, C.END, msg))


def warn(msg):
    print("{0}[!]{1} {2}".format(C.Y, C.END, msg))


def err(msg):
    print("{0}[-]{1} {2}".format(C.R, C.END, msg))


def banner():
    print(C.BOLD + C.B + r"""
   ____  _____ _____ _   _ _____   ____
  / __ \/ ___//  _/ | | / /_  __/  / __ \___  _________  ____
 / / / /\__ \ / /   | |/ / / /    / /_/ / _ \/ ___/ __ \/ __ \
/ /_/ /___/ // /    |   / / /    / _, _/  __/ /__/ /_/ / / / /
\____//____/___/    |_/ /_/     /_/ |_|\___/\___/\____/_/ /_/
   OSINT & Reconnaissance Orchestrator  -  authorized use only
""" + C.END)


def which(tool):
    """Return the path to a tool or None if it is not installed."""
    return shutil.which(tool)


# ---------------------------------------------------------------------------
# Command runner
# ---------------------------------------------------------------------------


class Recon:
    def __init__(self, target, outdir, args):
        self.target = target
        self.outdir = outdir
        self.args = args
        self.results = []  # list of dicts describing each step
        os.makedirs(outdir, exist_ok=True)
        self.rawdir = os.path.join(outdir, "raw")
        os.makedirs(self.rawdir, exist_ok=True)

    def run(self, name, tool, cmd, note=""):
        """Run one recon step.

        name  - short label used for the output file
        tool  - the binary the command needs (checked with `which`)
        cmd   - full command list
        note  - human-readable description shown in the report
        """
        binary = tool if isinstance(tool, str) else tool[0]
        if which(binary) is None:
            warn("Skipping {0} - '{1}' not installed".format(name, binary))
            self.results.append({
                "name": name, "note": note, "tool": binary,
                "status": "skipped (not installed)", "output_file": None,
            })
            return

        outfile = os.path.join(self.rawdir, "{0}.txt".format(name))
        info("Running {0} ({1}) ...".format(name, " ".join(cmd)))
        try:
            with open(outfile, "w") as fh:
                fh.write("# command: {0}\n\n".format(" ".join(cmd)))
                fh.flush()
                proc = subprocess.run(
                    cmd,
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                    timeout=self.args.timeout,
                )
            status = "ok" if proc.returncode == 0 else "exit {0}".format(proc.returncode)
            ok("{0} finished -> {1}".format(name, outfile))
        except subprocess.TimeoutExpired:
            status = "timeout after {0}s".format(self.args.timeout)
            warn("{0} timed out".format(name))
        except Exception as e:
            status = "error: {0}".format(e)
            err("{0} failed: {1}".format(name, e))

        self.results.append({
            "name": name, "note": note, "tool": binary,
            "status": status, "output_file": outfile,
        })

    # -- passive phase -----------------------------------------------------

    def passive(self):
        info("=== PASSIVE reconnaissance ===")
        t = self.target
        threads = str(self.args.threads)

        self.run("whois", "whois", ["whois", t],
                 "Domain registration / ownership records")

        self.run("dns_a", "dig", ["dig", "+nocmd", t, "ANY", "+multiline", "+noall", "+answer"],
                 "DNS records (A/AAAA/MX/NS/TXT/SOA)")

        self.run("dns_mx", "dig", ["dig", "+short", "MX", t],
                 "Mail exchanger records")

        self.run("dns_txt", "dig", ["dig", "+short", "TXT", t],
                 "TXT records (SPF/DMARC hints)")

        self.run("host", "host", ["host", "-a", t],
                 "Full host lookup")

        self.run("dnsrecon", "dnsrecon", ["dnsrecon", "-d", t],
                 "Standard DNS enumeration (records, SRV, wildcard)")

        self.run("dmitry", "dmitry", ["dmitry", "-winse", t],
                 "Whois + netcraft + subdomain + email harvest")

        # theHarvester: emails, hosts, names from public sources
        harvester = which("theHarvester") or which("theharvester")
        if harvester:
            self.run("theharvester", os.path.basename(harvester),
                     [os.path.basename(harvester), "-d", t, "-b", "all"],
                     "Emails / hosts / names from public search sources")
        else:
            warn("Skipping theharvester - not installed")
            self.results.append({"name": "theharvester", "note": "public OSINT",
                                 "tool": "theHarvester", "status": "skipped (not installed)",
                                 "output_file": None})

        # Subdomain discovery (passive sources)
        self.run("sublist3r", "sublist3r", ["sublist3r", "-d", t, "-o",
                 os.path.join(self.rawdir, "subdomains_sublist3r.txt")],
                 "Passive subdomain enumeration (search engines)")

        self.run("subfinder", "subfinder", ["subfinder", "-d", t, "-silent"],
                 "Passive subdomain enumeration (subfinder)")

        self.run("amass_passive", "amass",
                 ["amass", "enum", "-passive", "-d", t],
                 "Passive attack-surface mapping (OWASP Amass)")

        self.run("cert_crt", "curl",
                 ["curl", "-s", "https://crt.sh/?q=%25.{0}&output=json".format(t)],
                 "Certificate transparency subdomains (crt.sh)")

        self.run("whatweb", "whatweb", ["whatweb", "--no-errors", "-a", "1", t],
                 "Passive web technology fingerprinting")

        self.run("wafw00f", "wafw00f", ["wafw00f", t],
                 "Web application firewall detection")

    # -- active phase ------------------------------------------------------

    def active(self):
        info("=== ACTIVE reconnaissance (touches the target directly) ===")
        t = self.target
        threads = str(self.args.threads)

        self.run("nmap_quick", "nmap",
                 ["nmap", "-sV", "-sC", "-T4", "--top-ports", "1000",
                  "-oN", os.path.join(self.rawdir, "nmap_quick.gnmap"), t],
                 "Service/version scan of top 1000 TCP ports with default scripts")

        self.run("dnsenum", "dnsenum",
                 ["dnsenum", "--noreverse", "--threads", threads, t],
                 "DNS enumeration + subdomain brute force")

        self.run("fierce", "fierce", ["fierce", "--domain", t],
                 "DNS reconnaissance / subdomain brute force")

        self.run("whatweb_active", "whatweb",
                 ["whatweb", "--no-errors", "-a", "3", t],
                 "Aggressive web technology fingerprinting")

        self.run("sslscan", "sslscan", ["sslscan", t],
                 "TLS/SSL configuration and cipher review")

        # gobuster DNS brute force needs a wordlist
        if self.args.wordlist and which("gobuster"):
            self.run("gobuster_dns", "gobuster",
                     ["gobuster", "dns", "-d", t, "-w", self.args.wordlist,
                      "-t", threads, "-q"],
                     "Subdomain brute force (gobuster)")
        elif which("gobuster"):
            warn("Skipping gobuster_dns - no --wordlist provided")

        self.run("nikto", "nikto", ["nikto", "-host", t, "-maxtime",
                 str(self.args.timeout)],
                 "Web server misconfiguration / known-issue scan")

    # -- reporting ---------------------------------------------------------

    def report(self):
        summary_txt = os.path.join(self.outdir, "SUMMARY.txt")
        summary_json = os.path.join(self.outdir, "results.json")

        with open(summary_json, "w") as fh:
            json.dump({
                "target": self.target,
                "generated": datetime.datetime.now().isoformat(),
                "steps": self.results,
            }, fh, indent=2)

        lines = []
        lines.append("OSINT / Reconnaissance summary")
        lines.append("Target : {0}".format(self.target))
        lines.append("Date   : {0}".format(datetime.datetime.now().isoformat()))
        lines.append("Output : {0}".format(os.path.abspath(self.outdir)))
        lines.append("")
        lines.append("{0:<18} {1:<28} {2}".format("STEP", "STATUS", "DESCRIPTION"))
        lines.append("-" * 80)
        for r in self.results:
            lines.append("{0:<18} {1:<28} {2}".format(
                r["name"], r["status"], r["note"]))
        text = "\n".join(lines)

        with open(summary_txt, "w") as fh:
            fh.write(text + "\n")

        print("\n" + C.BOLD + text + C.END)
        ok("Full report written to {0}".format(os.path.abspath(self.outdir)))
        ok("Machine-readable results: {0}".format(summary_json))


# ---------------------------------------------------------------------------
# Authorization gate + entry point
# ---------------------------------------------------------------------------


def confirm_authorization(target, assume_yes):
    print(C.Y + C.BOLD +
          "\nLEGAL / AUTHORIZATION NOTICE".ljust(60) + C.END)
    print(C.Y +
          "Running reconnaissance against systems you are not authorized to\n"
          "test may be illegal. By continuing you confirm you have explicit,\n"
          "written permission to assess '{0}'.".format(target) + C.END)
    if assume_yes:
        warn("--yes supplied: authorization confirmed non-interactively.")
        return True
    try:
        answer = input(C.BOLD + "\nType 'yes' to confirm you are authorized: " + C.END).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer == "yes"


def parse_args():
    p = argparse.ArgumentParser(
        description="OSINT / reconnaissance orchestrator for authorized security engagements.",
        epilog="Passive gathering runs by default. Use --active to enable scans that touch the target.",
    )
    p.add_argument("target", help="Target domain, host, or IP you are authorized to assess")
    p.add_argument("-o", "--outdir", default=None,
                   help="Output directory (default: recon_<target>_<timestamp>)")
    p.add_argument("--active", action="store_true",
                   help="Also run active recon (nmap, brute-force DNS, nikto, etc.)")
    p.add_argument("--passive-only", action="store_true",
                   help="Force passive only even if --active is set")
    p.add_argument("-w", "--wordlist", default=None,
                   help="Wordlist for gobuster DNS brute force (active phase)")
    p.add_argument("-t", "--threads", type=int, default=20,
                   help="Threads for tools that support it (default 20)")
    p.add_argument("--timeout", type=int, default=600,
                   help="Per-tool timeout in seconds (default 600)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip the interactive authorization prompt (for automation)")
    return p.parse_args()


def main():
    banner()
    args = parse_args()
    target = args.target.strip()

    if not confirm_authorization(target, args.yes):
        err("Authorization not confirmed. Exiting.")
        sys.exit(1)

    if args.outdir:
        outdir = args.outdir
    else:
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = target.replace("/", "_").replace(":", "_")
        outdir = "recon_{0}_{1}".format(safe, stamp)

    recon = Recon(target, outdir, args)

    try:
        recon.passive()
        if args.active and not args.passive_only:
            recon.active()
        elif not args.active:
            info("Active phase skipped (pass --active to enable). Passive results only.")
    except KeyboardInterrupt:
        warn("Interrupted by user - writing partial report.")
    finally:
        recon.report()


if __name__ == "__main__":
    main()
