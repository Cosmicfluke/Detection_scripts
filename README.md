# Detection Scripts

A collection of PowerShell detection scripts for actively exploited or high-risk vulnerabilities, built for deployment via RMM tooling (NinjaOne) across Windows endpoint fleets.

These are **detection scripts, not prevention controls**. They flag behavioral artifacts associated with known exploitation techniques so you can respond quickly they don't stop an exploit from running.

## Scripts

### [`Rogue Planet (CVE-2026-50656)/`](./Rogue%20Planet%20%28CVE-2026-50656%29)
Detects indicators associated with **CVE-2026-50656 ("RoguePlanet")**, a high-severity elevation of privilege vulnerability in the Microsoft Malware Protection Engine (Microsoft Defender). No vendor patch is currently available.

**Checks for:**
1. `MsMpEng.exe` spawning a shell/interpreter process (highest-confidence signal)
2. Staging directories matching the exploit's known naming pattern
3. Disguised `wermgr.exe` copies, including the alternate data stream (ADS) artifact used by the exploit
4. The named pipe used by the public proof-of-concept while actively running
5. Recent unexpected modification of the legitimate `wermgr.exe` (weak/secondary signal)

**Testing status:** Checks 2–4 were validated by staging harmless decoy artifacts and confirming detection. Checks 1 and 5 are validated by code review only, safely reproducing them live would require either triggering a real privilege escalation or modifying a legitimate signed system file, neither of which is worth the risk purely to test a detection rule.

**Sources:**
- [Integrity360 Security Advisory: CVE-2026-50656](https://insights.integrity360.com/threat-advisories/security-advisory-cve-2026-50656-rogueplanet-microsoft-defender-elevation-of-privilege-vulnerability)
- Splunk Security Content
- Picus Security
- Cyderes / Guardsix

### [`Notepad++ supply chain attack 2025/`](./Notepad%2B%2B%20supply%20chain%20attack%202025)
Detects artifacts from the **"Chrysalis" backdoor**, delivered via a 2025 hijack of Notepad++'s update infrastructure, attributed with moderate confidence to the Lotus Blossom threat group.

**Checks for:**
1. A hidden staging folder (`AppData\Roaming\Bluetooth`) dropped by the malicious installer
2. The three files known to be dropped there: `BluetoothService.exe`, `log.dll`, and the extensionless `BluetoothService` (the actual encrypted payload)
3. SHA256 hash matches against Rapid7's full published IOC list (16 known-bad hashes across the installer, loader, and shellcode variants)
4. Whether the staging folder carries the Hidden attribute, matching the installer's known behavior

Note: this script uses a **three-tier exit code** (`0` clean / `1` suspect / `2` confirmed) rather than the binary `0`/`1` used elsewhere in this repo — see that script's own README for details.

**Testing status:** hashes verified as correctly formatted and copied directly from Rapid7's published table (an earlier draft had several malformed/mistyped hashes that would have silently never matched anything). Script executes cleanly end-to-end. The hash-match logic itself has not yet been tested against a deliberately staged matching file.

**Sources:**
- Rapid7: [The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/)
- The Hacker News, Kaspersky Securelist follow-up coverage

See the [full writeup](./Notepad%2B%2B%20supply%20chain%20attack%202025/Readme.md) in that folder for a plain-language explanation of the attack and what to do if this flags something.

## Deployment notes

- Designed to run as **SYSTEM** via an RMM (NinjaOne in our case) on a recurring schedule.
- Exit code `0` = clean, exit code `1` = one or more findings — check the script's stdout output for details.
- Polling interval matters: some indicators (like open named pipes) are only present for seconds while an exploit is actively running. Tighter intervals catch more; balance against endpoint load.
- These scripts are **detection only**. Where available, pair with a validated prevention control (e.g., WDAC/AppLocker in enforced mode for RoguePlanet) and standard patch management.

## Disclaimer

Provided as-is, with no warranty of any kind. These scripts are shared for the benefit of other defenders responding to the same threats **test in your own environment before deploying to production.** Detection logic is based on publicly available research at the time of writing and may not catch every variant of a given exploit, especially as attackers adapt.

## Contributing / feedback

Found a bug, a bypass, or have an improvement? Open an issue or a PR.

## License

MIT — see [LICENSE](./LICENSE).
