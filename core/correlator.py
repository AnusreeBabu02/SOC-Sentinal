"""
Temporal Attack-Chain Correlator
---------------------------------
Groups individual detections (MITRE rule hits + CVE exploit attempts) into
multi-stage incidents ("attack chains").

How it works
  1. A "signal event" is any event with a MITRE hit or a CVE exploit attempt.
  2. Signal events are linked when they share an entity (host or IP address)
     and occur within `window_min` minutes of the previous event on that entity.
     Linked events form an incident (union-find connected component), so a
     chain can span several hosts when they share an IP (e.g. the attacker).
  3. Each incident is ordered in time and its tactic sequence is compared with
     the ATT&CK kill-chain order and a set of known attack playbooks.
  4. Incidents with at least `min_stages` distinct tactics are reported and
     scored 0-100:

        score = 10*distinct_tactics + 2*rule_weight_sum + 15*playbooks_matched
                + 10*kill_chain_progression + max_cvss + 5*min(anomalies, 3)

     (capped at 100). Levels: >=70 critical, >=45 high, >=25 medium, else low.
"""

import ipaddress

import pandas as pd

from core.mitre_rules import TACTIC_ORDER

GENERIC_HOSTS = {"unknown-host", "web-server", "unknown"}   # too generic to link on
IGNORED_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}

# CVE exploit attempts count as an ATT&CK stage. Default = Initial Access;
# local / post-exploitation CVEs are overridden here.
DEFAULT_CVE_TACTIC = "Initial Access"
CVE_TACTIC = {
    "CVE-2021-4034": "Privilege Escalation",
    "CVE-2021-3156": "Privilege Escalation",
    "CVE-2020-1472": "Privilege Escalation",
    "CVE-2021-34527": "Privilege Escalation",
    "CVE-2017-0144": "Lateral Movement",
}

# Ordered steps; each step is a set of acceptable tactics (subsequence match).
_FOOTHOLD = {"Initial Access", "Execution", "Credential Access", "Persistence", "Lateral Movement"}
PLAYBOOKS = [
    ("Brute force → account takeover → privilege escalation",
     [{"Credential Access"}, {"Persistence", "Privilege Escalation"}]),
    ("Exploitation → persistence → command & control",
     [{"Initial Access"}, {"Persistence", "Execution"}, {"Command and Control"}]),
    ("Credential theft → lateral movement",
     [{"Credential Access"}, {"Lateral Movement"}]),
    ("Defense evasion → payload execution",
     [{"Defense Evasion"}, {"Execution", "Command and Control", "Impact"}]),
    ("Intrusion → ransomware impact",
     [_FOOTHOLD, {"Impact"}]),
]

_STAGE_IDX = {t: i for i, t in enumerate(TACTIC_ORDER)}


def _idx(tactic):
    return _STAGE_IDX.get(tactic, 99)


class _DSU:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def _valid_ip(ip):
    if ip in IGNORED_IPS:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _stages(row):
    """Return [(tactic, weight)] for one event."""
    out = []
    for h in row["mitre_hits"]:
        out.append((h["tactic"], float(h["severity_weight"])))
    for h in row["cve_hits"]:
        if h["evidence"] == "exploit_attempt":
            out.append((CVE_TACTIC.get(h["cve_id"], DEFAULT_CVE_TACTIC), (h["cvss"] or 5.0) / 2))
    return out


def _entity_keys(row):
    keys = set()
    if row["host"] not in GENERIC_HOSTS:
        keys.add(f"host:{row['host']}")
    for ip in row["iocs"].get("ips", []):
        if _valid_ip(ip):
            keys.add(f"ip:{ip}")
    return keys


def _matches(seq, steps):
    i = 0
    for t in seq:
        if t in steps[i]:
            i += 1
            if i == len(steps):
                return True
    return False


def _level(score):
    return "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 25 else "low"


def correlate_events(df, window_min=30, min_stages=2):
    """
    Returns (df, chains).
      df gains columns: chain_id (str|None), chain_stage (primary tactic|None)
      chains: list of dicts sorted by score (desc)
    """
    df = df.copy()
    df["chain_id"] = None
    df["chain_stage"] = None
    window = pd.Timedelta(minutes=window_min)

    # --- 1. collect signal events -------------------------------------------
    sig = []   # (timestamp, index, stages)
    for idx, row in df.iterrows():
        if pd.isnull(row["timestamp"]):
            continue
        st_list = _stages(row)
        if st_list:
            sig.append((row["timestamp"], idx, st_list))
            df.at[idx, "chain_stage"] = max(st_list, key=lambda s: s[1])[0]
    sig.sort(key=lambda x: (x[0], x[1]))

    # --- 2. link by shared entity within the time window ----------------------
    dsu = _DSU()
    last_seen = {}
    for ts, idx, _ in sig:
        dsu.find(idx)
        for key in _entity_keys(df.loc[idx]):
            if key in last_seen and ts - last_seen[key][1] <= window:
                dsu.union(idx, last_seen[key][0])
            last_seen[key] = (idx, ts)

    groups = {}
    for ts, idx, st_list in sig:
        groups.setdefault(dsu.find(idx), []).append((ts, idx, st_list))

    # --- 3. build + score chains ------------------------------------------------
    chains = []
    for members in groups.values():
        members.sort(key=lambda x: (x[0], x[1]))
        full_seq = []
        for _, _, st_list in members:
            full_seq += [t for t, _ in sorted(st_list, key=lambda s: _idx(s[0]))]

        tactics = list(dict.fromkeys(full_seq))          # first-occurrence order
        if len(tactics) < min_stages:
            continue

        idxs = [m[1] for m in members]
        sub = df.loc[idxs]

        rule_w, cve_ids, max_cvss = {}, set(), 0.0
        for _, r in sub.iterrows():
            for h in r["mitre_hits"]:
                rule_w[h["rule_id"]] = h["severity_weight"]
            for h in r["cve_hits"]:
                if h["evidence"] != "mentioned":
                    cve_ids.add(h["cve_id"])
                    max_cvss = max(max_cvss, h["cvss"] or 0.0)
        anomalies = int(sub["ml_anomaly"].sum())

        pairs = list(zip(tactics, tactics[1:]))
        progression = (sum(_idx(a) <= _idx(b) for a, b in pairs) / len(pairs)) if pairs else 0.0
        playbooks = [name for name, steps in PLAYBOOKS if _matches(full_seq, steps)]

        score = (10 * len(tactics) + 2 * sum(rule_w.values()) + 15 * len(playbooks)
                 + 10 * progression + max_cvss + 5 * min(anomalies, 3))
        score = int(min(100, round(score)))

        start, end = members[0][0], members[-1][0]
        hosts = sorted(set(sub["host"]))
        ips = sorted({ip for _, r in sub.iterrows() for ip in r["iocs"].get("ips", []) if _valid_ip(ip)})
        duration = round((end - start).total_seconds() / 60, 1)
        path = " → ".join(tactics)

        chains.append({
            "chain_id": None, "score": score, "level": _level(score),
            "start": start, "end": end, "duration_min": duration,
            "hosts": hosts, "ips": ips, "n_events": len(idxs), "event_idx": idxs,
            "tactics": tactics, "path": path,
            "techniques": sorted({h["technique_id"] for _, r in sub.iterrows() for h in r["mitre_hits"]}),
            "cves": sorted(cve_ids), "max_cvss": max_cvss,
            "playbooks": playbooks, "anomalies": anomalies,
            "progression": round(progression, 2),
            "narrative": f"{path} across {', '.join(hosts)} — {len(idxs)} events over {duration} min",
        })

    chains.sort(key=lambda c: (-c["score"], c["start"]))
    for n, c in enumerate(chains, 1):
        c["chain_id"] = f"INC-{n:03d}"
        df.loc[c["event_idx"], "chain_id"] = c["chain_id"]
    return df, chains
