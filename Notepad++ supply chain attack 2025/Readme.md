# Notepad++ Supply Chain Attack (2025) — Chrysalis Backdoor Detection

## What happened, in plain terms

Between June and December 2025, attackers compromised the **hosting infrastructure** behind Notepad++'s update system — not the Notepad++ source code itself, and not the notepad-plus-plus.org website's application logic, but the servers responsible for delivering updates to users.

For a targeted set of users, when Notepad++ checked for updates, it was silently redirected to a malicious server instead of the real one. That server served a booby-trapped installer instead of a genuine update.

This wasn't a mass attack — it was **highly selective**. Researchers at Rapid7 (with follow-up analysis from Kaspersky and others) attribute it with moderate confidence to **Lotus Blossom**, a Chinese state-linked espionage group that's been active since roughly 2009, historically targeting government, telecom, and critical infrastructure organizations, mostly across Southeast Asia and more recently Latin America.

## What the malicious update actually did

The fake installer (`update.exe`) quietly did the following:
1. Created a hidden folder called `Bluetooth` inside the user's `AppData\Roaming` folder.
2. Dropped three files into it:
   - **`BluetoothService.exe`** — a real, legitimate file (a renamed Bitdefender component), abused to load something it shouldn't.
   - **`log.dll`** — a malicious file disguised as a normal system DLL, which is what actually gets loaded by the file above.
   - **`BluetoothService`** (no file extension) — the real payload, encrypted so it doesn't look like a program at all until it's decrypted and run.
3. Once running, this delivered a custom backdoor researchers named **"Chrysalis"** — giving the attacker a foothold to gather information and communicate with a remote server for further instructions.

Notepad++'s maintainer has since hardened the update mechanism (verifying certificates and signatures on downloads) and moved to a more secure hosting provider, so this specific method of attack shouldn't work against current versions.

## What this script does

It checks any machine it runs on for **leftover evidence** that this specific attack happened, even if it happened months ago and nothing looks obviously wrong day-to-day. In plain terms, it looks for:

1. **The hidden staging folder** — does a folder matching the attacker's pattern exist in any user's profile?
2. **The three dropped files** — are any of `BluetoothService.exe`, `log.dll`, or the extensionless `BluetoothService` sitting in that folder?
3. **A hash match** — for any of those files it finds, it calculates a unique fingerprint (a SHA256 hash) and compares it against a list of fingerprints for files confirmed malicious by Rapid7's investigation. A match means "this is provably the exact malicious file," not just "something with this name exists."
4. **Whether the folder is hidden** — a genuine extra clue, since the attacker's installer specifically set this folder to be hidden from normal view.

It also reports whether Notepad++ is installed and which version, just as background context — that part isn't used to decide anything, since simply having Notepad++ installed doesn't mean you were targeted.

## What the results mean

- **Clean** — no trace of any of this on the machine.
- **Suspect** — the staging folder exists, but nothing hashed out as a confirmed match. Worth investigating manually, but not proof of compromise.
- **Confirmed** — an actual file on the machine matches a known-malicious fingerprint. Treat this as a real incident: isolate the machine and escalate immediately.

## What to do if it flags something

- **Confirmed hit:** disconnect the machine from the network, don't delete anything (preserve evidence), and escalate to your incident response process immediately. This is a backdoor with remote access capability, not a false alarm to shrug off.
- **Suspect hit:** manually inspect the flagged folder, check when it was created, and consider running a fuller antivirus/EDR scan on that machine before ruling it out.

## Testing status

- Verified all 16 hashes are correctly formatted (a first draft had several malformed entries that would have silently never matched anything — since fixed) and copied directly from Rapid7's published IOC table rather than retyped by hand.
- Script executes cleanly end-to-end and correctly reports clean/no-match results on a machine without Notepad++ installed.
- The hash-comparison logic itself has not yet been tested against a deliberately staged file with a matching hash — worth doing before relying on this at scale, same caveat as the "code review only" checks in the RoguePlanet script in this repo.

## Sources

- Ivan Feigl, ["The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit"](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/), Rapid7
- [Notepad++ Hosting Breach Attributed to China-Linked Lotus Blossom Hacking Group](https://thehackernews.com/2026/02/notepad-hosting-breach-attributed-to.html), The Hacker News
- Kaspersky Securelist follow-up analysis and additional IOCs
