# Sigma Detection Lab

Sigma detection rules for Windows, Linux and AWS, where every rule is tested on both sides: it has to fire on the attack and stay quiet on the benign lookalike.

[![Validate detection rules](https://github.com/coderx0319/sigma-detection-lab/actions/workflows/validate.yml/badge.svg)](https://github.com/coderx0319/sigma-detection-lab/actions/workflows/validate.yml)
![Rules](https://img.shields.io/badge/rules-10-blue)
![Detection tests](https://img.shields.io/badge/detection%20tests-44%20passing-success)
![ATT&CK](https://img.shields.io/badge/ATT%26CK%20techniques-12-red)
![Python](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

## Why I built this

Writing a detection rule is easy. Knowing that it works is not.

A rule that never fires looks exactly like a quiet network, because both produce zero alerts. That silence reads as safety, which is what makes it dangerous. A rule that fires on every software deployment has the opposite problem: it gets muted inside a week, and once it is muted it is gone.

So this repo treats detections like code. Every rule ships with test cases on both sides of the line:

* a true positive case, proving the rule fires on the behaviour it claims to detect
* one or more true negative cases of benign activity that looks similar, which are the events that generate the false positives analysts learn to ignore

A rule is not finished until it passes both. CI runs the whole suite on every push.

## Quick start

```bash
pip install -r requirements.txt

python validate.py              # validate schemas and run every detection test
python validate.py --coverage   # also print the ATT&CK coverage table
python validate.py --rule lsass # narrow to one rule while tuning it

python -m pytest tests/ -v      # same checks, one test per case
```

`validate.py` exits non zero if any rule fails its schema check or any detection test, so it drops straight into a pipeline.

Sample output:

```
RULE                                  | TEST CASE                          | RESULT | DETAIL
--------------------------------------+------------------------------------+--------+-----------------------
PowerShell Encoded Command Execution  | encoded payload spawned by Word    | PASS   | fired as expected
PowerShell Encoded Command Execution  | SCCM wrapper is excluded by filter | PASS   | correctly stayed quiet
LSASS Process Memory Access           | rundll32 comsvcs minidump of LSASS | PASS   | fired as expected
LSASS Process Memory Access           | low-privilege query handle only    | PASS   | correctly stayed quiet

ALL CHECKS PASSED
  rules with schema errors : 0
  detection tests run      : 44
  detection tests passed   : 44
  detection tests failed   : 0
```

## Rules

| Rule | Platform | ATT&CK | Level |
|---|---|---|---|
| [PowerShell Encoded Command Execution](rules/windows/powershell_encoded_command.yml) | Windows | T1059.001, T1027 | High |
| [LSASS Process Memory Access](rules/windows/lsass_credential_access.yml) | Windows | T1003.001 | Critical |
| [Scheduled Task From a User-Writable Path](rules/windows/scheduled_task_persistence.yml) | Windows | T1053.005 | High |
| [Defender Exclusion Added via PowerShell](rules/windows/defender_exclusion_added.yml) | Windows | T1562.001 | High |
| [Volume Shadow Copy Deletion](rules/windows/shadow_copy_deletion.yml) | Windows | T1490 | Critical |
| [Reverse Shell Invocation](rules/linux/reverse_shell_execution.yml) | Linux | T1059.004 | Critical |
| [Crontab Modified From a Suspicious Path](rules/linux/cron_persistence.yml) | Linux | T1053.003 | High |
| [Sensitive Credential File Read](rules/linux/shadow_file_access.yml) | Linux | T1003.008, T1552.004 | Critical |
| [AWS Root Account Console Login](rules/cloud/aws_root_console_login.yml) | AWS | T1078.004 | High |
| [CloudTrail Logging Disabled or Deleted](rules/cloud/aws_cloudtrail_tampering.yml) | AWS | T1562.008 | Critical |

That covers 12 ATT&CK techniques across initial access, execution, persistence, privilege escalation, defence evasion, credential access and impact.

## How it works

```
rules/**/*.yml  ->  loader.py   ->  matcher.py  ->  report.py
  Sigma YAML        schema and      evaluate        PASS/FAIL table
                    duplicate id    condition       and ATT&CK coverage
                    checks          against event
```

| Module | What it does |
|---|---|
| `src/loader.py` | Parses the rule YAML and enforces the required Sigma fields, a valid `level` and `status`, a usable `logsource`, and no duplicate rule IDs. A duplicate ID silently breaks SIEM deployment, so it is worth catching early. |
| `src/matcher.py` | Evaluates Sigma detection logic against a single event. Handles field modifiers (`contains`, `startswith`, `endswith`, `re`, `all`), wildcards, list as OR semantics, and a recursive descent parser for the condition grammar (`and`, `or`, `not`, parentheses, `1 of selection_*`, `all of them`). |
| `src/report.py` | Renders the results table, the ATT&CK coverage matrix and the run summary. |
| `validate.py` | CLI entry point with pipeline friendly exit codes. |
| `tests/test_rules.py` | Pytest wrapper giving one test per rule and case pair, so a failure names the exact case. |

The matcher covers the subset of the Sigma spec these rules use, including the case insensitive string matching that Sigma defaults to. I wrote it rather than pulling in pySigma on purpose, because writing the evaluator is how you learn what a detection rule actually asserts.

## Adding a rule

1. Drop the rule in `rules/<platform>/<name>.yml` with ATT&CK tags and a realistic `falsepositives` section.
2. Add `tests/testcases/<name>.json` with at least one true positive and one true negative:

```json
{
  "rule": "rules/windows/my_rule.yml",
  "cases": [
    { "name": "the attack",      "expect": true,  "event": { "Image": "...", "CommandLine": "..." } },
    { "name": "the benign twin", "expect": false, "event": { "Image": "...", "CommandLine": "..." } }
  ]
}
```

3. Run `python validate.py --rule my_rule` and tune until both sides pass.

The harness fails any rule with no test cases and any rule with no ATT&CK tag, so coverage cannot quietly rot.

## Limitations worth knowing

* **Single event matching only.** A Sigma rule describes one event. Real correlation, like brute force followed by a success, beaconing intervals or impossible travel, needs state across events and belongs in the SIEM layer rather than here.
* **Field names are source specific.** The Windows rules assume Sysmon style field names such as `Image`, `CommandLine` and `GrantedAccess`. Pointing them at a different pipeline means remapping fields first, and a wrong field name gives you a rule that never fires and never errors.
* **The true negatives are representative, not exhaustive.** They encode the false positives documented in each rule. Proper tuning needs real telemetry from the estate the rule will run in.
* **Filters trade detection for noise.** The Defender exclusion in the LSASS rule is a choice: an attacker running from the Defender platform directory would be missed. That is a documented gap rather than an oversight.

## Author

Shantanu Vedante, MSc Cyber Security, University of Kent.
[LinkedIn](https://www.linkedin.com/in/shantanuvedante03/) · [Portfolio](https://shantanuvedantetechie.vercel.app/)

Part of a blue team portfolio alongside [ThreatLens](https://github.com/coderx0319/ThreatLens-CVE) for CVE prioritisation and [PhishGuard](https://github.com/coderx0319/PhishGuard) for phishing triage.

## License

MIT, see [LICENSE](LICENSE).
