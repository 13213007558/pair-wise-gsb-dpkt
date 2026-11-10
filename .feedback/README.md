# Feedback task starting environment

Upstream: https://github.com/kbandla/dpkt
Upstream commit: `4f8958eb4b375b38d0ab6ffadf2da9b24395394d`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= dpkt/dns.py dpkt/ip.py dpkt/pcap.py dpkt/pcapng.py dpkt/ssl.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-10): `148 passed, 4 warnings in 0.72s`
Whole-command wall time: 1.069 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
