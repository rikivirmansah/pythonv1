#!/usr/bin/env python3
import os
import re
import telnetlib
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from contextlib import contextmanager

# ================== KONFIG ==================
HOST = "136.1.1.100"
PORT = 23
USERNAME = "zte"
PASSWORD = "zte"

TIMEOUT = 30
SHOW_TIMEOUT = 180
CMD_DELAY = 0.01

# PATCH: prompt regex aman (hindari karakter aneh)
PROMPT_ANY_REGEX = re.compile(rb"ZXAN(?:\([^)]+\))?#\s*$", re.MULTILINE)
PROMPT_EXEC_REGEX = re.compile(rb"ZXAN#\s*$", re.MULTILINE)

LOGIN_USER = [b"Username:", b"username:", b"Login:", b"login:"]
LOGIN_PASS = [b"Password:", b"password:"]

DEFAULT_VLANS = [1002, 1001, 996, 33, 31, 30, 27, 25, 24, 1006, 562, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6]
PROV_VLANS: List[int] = DEFAULT_VLANS.copy()
DEFAULT_ONU_TYPE = ""

VERIFY_MAX_WAIT_SEC = 0.8
VERIFY_POLL_INTERVAL_SEC = 0.2

WR_AFTER_EACH_SUCCESS = True
WR_DELAY_SEC = 0.2

MAX_PROV_ROUNDS = 10
SLEEP_BETWEEN_ROUNDS_SEC = 0.5

START_ONU_ID = 1
MAX_ONU_ID = 64

OPTIC_CACHE_TTL_SEC = 30.0

RUNCFG_CACHE_TTL_SEC = 20.0
RUNCFG_CACHE: Tuple[float, str] = (0.0, "")

# ================== UTIL ==================
def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def looks_like_error(out: str) -> bool:
    t = out.lower()
    err_keys = ["%error", "invalid", "fail", "failed", "unknown", "incomplete",
                "ambiguous", "denied", "not supported", "error"]
    return any(k in t for k in err_keys)

def extract_error_snippet(out: str, max_lines: int = 25) -> str:
    lines = [ln.rstrip() for ln in out.splitlines()]
    keys = ["%error", "invalid", "fail", "failed", "unknown", "incomplete",
            "ambiguous", "denied", "not supported", "error"]
    err_lines = [ln for ln in lines if any(k in ln.lower() for k in keys)]
    tail = lines[-max_lines:] if len(lines) > max_lines else lines
    merged, seen = [], set()
    for ln in err_lines + ["--- tail ---"] + tail:
        if ln not in seen and ln.strip():
            merged.append(ln)
            seen.add(ln)
    return "\n".join(merged).strip()

def uniq_int_list(vals: List[int]) -> List[int]:
    return sorted({int(v) for v in vals if str(v).isdigit()})

def parse_csv_ints(s: str) -> List[int]:
    s = s.strip()
    if not s:
        return []
    out: List[int] = []
    for p in s.split(","):
        p = p.strip()
        if not p:
            continue
        if "-" in p:
            a, b = [x.strip() for x in p.split("-", 1)]
            if a.isdigit() and b.isdigit():
                aa, bb = int(a), int(b)
                if aa > bb:
                    aa, bb = bb, aa
                out.extend(list(range(aa, bb + 1)))
        else:
            if p.isdigit():
                out.append(int(p))
    return sorted(set(out))

def compress_ranges(nums: List[int]) -> str:
    nums = sorted(set(int(x) for x in nums if str(x).isdigit()))
    if not nums:
        return ""
    ranges = []
    start = prev = nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
            continue
        ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
        start = prev = n
    ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
    return ",".join(ranges)

def chunk_vlan_cmd_ranges(nums: List[int], max_len: int = 180) -> List[str]:
    nums = sorted(set(nums))
    if not nums:
        return []
    chunks: List[List[int]] = []
    cur: List[int] = []
    for n in nums:
        cur.append(n)
        s = compress_ranges(cur)
        if len(s) > max_len:
            cur.pop()
            chunks.append(cur)
            cur = [n]
    if cur:
        chunks.append(cur)
    return [compress_ranges(c) for c in chunks if c]

def olt_root_from_port(olt_port: str) -> Optional[str]:
    m = re.search(r"(epon-olt_\d+/\d+)(?:/\d+)?$", olt_port, re.IGNORECASE)
    return m.group(1).lower() if m else None

def onu_prefix_from_olt_port(olt_port: str) -> Optional[str]:
    m = re.search(r"epon-olt_(\d+/\d+/\d+)$", olt_port, re.IGNORECASE)
    if not m:
        return None
    return f"epon-onu_{m.group(1)}:"

# ===== MAC helper =====
def normalize_mac_or_prefix(s: str) -> Optional[str]:
    if not s:
        return None
    t = s.strip().lower()
    t = re.sub(r"[^0-9a-f]", "", t)
    if not re.fullmatch(r"[0-9a-f]+", t):
        return None
    if len(t) == 12:
        return f"{t[0:4]}.{t[4:8]}.{t[8:12]}"
    if len(t) == 8:
        return f"{t[0:4]}.{t[4:8]}"
    if len(t) == 6:
        return f"{t[0:4]}.{t[4:6]}"
    return None

def parse_mac_inputs(raw: str) -> List[str]:
    if not raw:
        return []
    parts = re.split(r"[,\s]+", raw.strip())
    out: List[str] = []
    seen = set()
    for p in parts:
        if not p.strip():
            continue
        nm = normalize_mac_or_prefix(p)
        if nm and nm not in seen:
            out.append(nm)
            seen.add(nm)
    return out

def mac_match(found_mac: str, target: str) -> bool:
    fm = (found_mac or "").lower()
    tg = (target or "").lower()
    return fm == tg or fm.startswith(tg)

# ================== LOGGING ==================
class Logger:
    def __init__(self, filename: str):
        self.filename = filename
        self.silent = False
        with open(self.filename, "w", encoding="utf-8") as f:
            f.write(f"[{ts()}] LOG START\n")

    def info(self, msg: str):
        line = f"[{ts()}] {msg}"
        if not self.silent:
            print(line, flush=True)
        with open(self.filename, "a", encoding="utf-8") as f:
            f.write(line + "\n")

@contextmanager
def silent(logger: Logger):
    old = logger.silent
    logger.silent = True
    try:
        yield
    finally:
        logger.silent = old

# ================== DATA/PARSER ==================
@dataclass
class OnuDeny:
    onu_no: int
    mac: Optional[str]
    sn: Optional[str]
    model: Optional[str] = None

@dataclass
class OnuPass:
    onu_no: int
    onu_type: Optional[str]
    mgmt_mac: Optional[str]
    last_auth_time: Optional[str]

@dataclass
class OnuOptic:
    onu_tx_up_dbm: Optional[float] = None
    onu_rx_down_dbm: Optional[float] = None

def parse_mac_sn_from_unauth_block(text: str) -> Tuple[Optional[str], Optional[str]]:
    mac = None
    sn = None
    m_mac = re.search(r"MAC address\s*:\s*([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})", text, re.IGNORECASE)
    if m_mac:
        mac = m_mac.group(1).lower()
    m_sn = re.search(r"^\s*SN\s*:\s*(\S+)\s*$", text, re.IGNORECASE | re.MULTILINE)
    if m_sn:
        sn = m_sn.group(1)
    return mac, sn

def parse_unauthentication_blocks(text: str) -> List[OnuDeny]:
    items: List[OnuDeny] = []
    blocks = re.split(r"\n\s*\n", text)
    for b in blocks:
        m_if = re.search(r"Onu interface\s*:\s*epon-onu_\d+/\d+/\d+:(\d+)", b, re.IGNORECASE)
        m_state = re.search(r"Online State\s*:\s*authentication deny", b, re.IGNORECASE)
        if not (m_if and m_state):
            continue
        onu_no = int(m_if.group(1))
        mac, sn = parse_mac_sn_from_unauth_block(b)
        m_model = re.search(r"(Onu\s+Model|Model)\s*:\s*(.+)", b, re.IGNORECASE)
        model = m_model.group(2).strip() if m_model else None
        items.append(OnuDeny(onu_no=onu_no, mac=mac, sn=sn, model=model))
    items.sort(key=lambda x: x.onu_no)
    return items

def parse_authentication_blocks(text: str) -> List[OnuPass]:
    items: List[OnuPass] = []
    blocks = re.split(r"\n\s*\n", text)
    for b in blocks:
        m_if = re.search(r"Onu interface\s*:\s*epon-onu_\d+/\d+/\d+:(\d+)", b, re.IGNORECASE)
        m_state = re.search(r"Online State\s*:\s*authentication pass", b, re.IGNORECASE)
        if not (m_if and m_state):
            continue
        onu_no = int(m_if.group(1))
        m_type = re.search(r"Onu type\s*:\s*(\S+)", b, re.IGNORECASE)
        onu_type = m_type.group(1).strip() if m_type else None
        m_mgmt_mac = re.search(r"Mgmt MAC\s*:\s*([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})", b, re.IGNORECASE)
        mgmt_mac = m_mgmt_mac.group(1).lower() if m_mgmt_mac else None
        m_last = re.search(r"LastAuthTime\s*:\s*(.+)", b, re.IGNORECASE)
        last_auth = m_last.group(1).strip() if m_last else None
        items.append(OnuPass(onu_no=onu_no, onu_type=onu_type, mgmt_mac=mgmt_mac, last_auth_time=last_auth))
    items.sort(key=lambda x: x.onu_no)
    return items

def parse_service_ports(text: str) -> Dict[int, int]:
    ports: Dict[int, int] = {}
    for m in re.finditer(
        r"service-port\s+(\d+)\s+vport\s+\d+\s+user-vlan\s+(\d+)\s+vlan\s+(\d+)",
        text, re.IGNORECASE
    ):
        try:
            sp_id = int(m.group(1))
            vlan = int(m.group(3))
            ports[sp_id] = vlan
        except Exception:
            pass
    return ports

# PATCH dbm parsing aman
def parse_pon_power_attenuation(text: str) -> OnuOptic:
    m_up = re.search(
        r"^\s*up\s+Rx\s*:\s*([+-]?\d+(?:\.\d+)?)\s*\(dbm\)\s+Tx\s*:\s*([+-]?\d+(?:\.\d+)?)",
        text, re.IGNORECASE | re.MULTILINE
    )
    m_dn = re.search(
        r"^\s*down\s+Tx\s*:\s*([+-]?\d+(?:\.\d+)?)\s*\(dbm\)\s+Rx\s*:\s*([+-]?\d+(?:\.\d+)?)",
        text, re.IGNORECASE | re.MULTILINE
    )
    up_tx = float(m_up.group(2)) if m_up else None
    dn_rx = float(m_dn.group(2)) if m_dn else None
    return OnuOptic(onu_tx_up_dbm=up_tx, onu_rx_down_dbm=dn_rx)

# ================== TELNET CORE ==================
class ZXAN:
    def __init__(self, host: str, port: int, log: Logger):
        self.log = log
        self.tn = telnetlib.Telnet(host, port, TIMEOUT)
        self.log.info(f"Connected TCP {host}:{port}")

    def flush(self):
        _ = self.tn.read_very_eager()

    def read_until_any_prompt(self, timeout: int, label: str) -> str:
        idx, _, data = self.tn.expect([PROMPT_ANY_REGEX], timeout)
        out = data.decode(errors="ignore")
        if idx < 0:
            raise TimeoutError(f"Timeout waiting prompt ({label}).")
        return out

    def read_until_exec(self, timeout: int, label: str) -> str:
        idx, _, data = self.tn.expect([PROMPT_EXEC_REGEX], timeout)
        out = data.decode(errors="ignore")
        if idx < 0:
            raise TimeoutError(f"Timeout waiting EXEC prompt ({label}).")
        return out

    def send_wait_any(self, cmd: str, timeout: int, label: str) -> str:
        self.flush()
        self.log.info(f"SEND: {cmd}")
        self.tn.write(cmd.encode() + b"\n")
        if CMD_DELAY > 0:
            time.sleep(CMD_DELAY)
        return self.read_until_any_prompt(timeout, label)

    def send_wait_exec(self, cmd: str, timeout: int, label: str) -> str:
        self.flush()
        self.log.info(f"SEND: {cmd}")
        self.tn.write(cmd.encode() + b"\n")
        if CMD_DELAY > 0:
            time.sleep(CMD_DELAY)
        return self.read_until_exec(timeout, label)

    def login_fast(self, username: str, password: str):
        self.log.info("LOGIN: fast")
        self.tn.write(b"\n")
        time.sleep(0.2)
        idx, _, _ = self.tn.expect(LOGIN_USER + [PROMPT_ANY_REGEX], 10)
        if idx == len(LOGIN_USER):
            self.log.info("LOGIN OK (already logged in)")
            return
        self.tn.write(username.encode() + b"\n")
        self.tn.expect(LOGIN_PASS, 10)
        self.tn.write(password.encode() + b"\n")
        self.tn.expect([PROMPT_ANY_REGEX], 15)
        self.log.info("LOGIN OK")

    def close(self):
        self.log.info("CLOSE: exit")
        try:
            self.tn.write(b"exit\n")
        except Exception:
            pass
        self.tn.close()

# ================== MODE HELPERS ==================
def go_exec(z: ZXAN):
    z.send_wait_any("end", 20, "go-exec-end")
    z.send_wait_exec("", 5, "go-exec-confirm")

def ensure_exec(z: ZXAN):
    go_exec(z)

def enter_config(z: ZXAN):
    ensure_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg")

def enter_olt(z: ZXAN, olt_if: str):
    # hierarchy "interface epon" -> sesuai request
    ensure_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg")
    z.send_wait_any("interface epon", 20, "if-epon")
    z.send_wait_any("interface epon-olt", 20, "if-epon-olt")
    z.send_wait_any(f"interface {olt_if}", 20, "if-olt-target")

def end_wr(z: ZXAN):
    ensure_exec(z)
    z.send_wait_exec("wr", 180, "wr")

def wr_after_each(z: ZXAN, note: str = ""):
    if not WR_AFTER_EACH_SUCCESS:
        return
    if note:
        print(f"   -> END+WR ({note})")
    end_wr(z)
    if WR_DELAY_SEC > 0:
        time.sleep(WR_DELAY_SEC)

# ================== RUNNING-CONFIG CACHE ==================
def get_running_config_cached(z: ZXAN, force: bool = False) -> str:
    global RUNCFG_CACHE
    t0, txt = RUNCFG_CACHE
    now = time.time()
    if (not force) and txt and (now - t0 <= RUNCFG_CACHE_TTL_SEC):
        return txt
    with silent(z.log):
        enter_config(z)
        out = z.send_wait_any("show running-config", SHOW_TIMEOUT, "show-running-config")
        ensure_exec(z)
    RUNCFG_CACHE = (now, out)
    return out

# ================== SHOW ==================
def show_unauthentication(z: ZXAN, olt_if: str, quiet: bool = False) -> str:
    if quiet:
        with silent(z.log):
            enter_config(z)
            out = z.send_wait_any(f"show onu unauthentication {olt_if}", SHOW_TIMEOUT, "show-unauthentication")
            ensure_exec(z)
            return out
    enter_config(z)
    out = z.send_wait_any(f"show onu unauthentication {olt_if}", SHOW_TIMEOUT, "show-unauthentication")
    ensure_exec(z)
    return out

def show_authentication(z: ZXAN, olt_if: str, quiet: bool = False) -> str:
    if quiet:
        with silent(z.log):
            enter_config(z)
            out = z.send_wait_any(f"show onu authentication {olt_if}", SHOW_TIMEOUT, "show-authentication")
            ensure_exec(z)
            return out
    enter_config(z)
    out = z.send_wait_any(f"show onu authentication {olt_if}", SHOW_TIMEOUT, "show-authentication")
    ensure_exec(z)
    return out

def show_pon_power_attenuation(z: ZXAN, onu_if: str) -> str:
    with silent(z.log):
        ensure_exec(z)
        return z.send_wait_any(f"show pon power attenuation {onu_if}", 30, f"pon-power-{onu_if}")

# ===== OPTIC CACHE =====
OPTIC_CACHE: Dict[str, Tuple[float, OnuOptic]] = {}

def get_onu_optic_cached(z: ZXAN, onu_if: str) -> OnuOptic:
    k = onu_if.lower()
    now = time.time()
    if k in OPTIC_CACHE:
        t0, val = OPTIC_CACHE[k]
        if now - t0 <= OPTIC_CACHE_TTL_SEC:
            return val
    out = show_pon_power_attenuation(z, onu_if)
    val = OnuOptic()
    if not looks_like_error(out):
        val = parse_pon_power_attenuation(out)
    OPTIC_CACHE[k] = (now, val)
    return val

# ================== DISCOVERY ALL PORTS ==================
def discover_root_cards_from_help(z: ZXAN) -> List[str]:
    ensure_exec(z)
    out = z.send_wait_any("show interface ?", SHOW_TIMEOUT, "discover-root-help")
    roots = sorted(set(re.findall(r"\b(epon-olt_\d+/\d+)\b", out, flags=re.IGNORECASE)))
    return [r.lower() for r in roots]

def expand_ports_from_root(root: str, ports_per_card: int = 8) -> List[str]:
    return [f"{root}/{i}" for i in range(1, ports_per_card + 1)]

def count_registered_on_port(z: ZXAN, port: str) -> Tuple[int, int, int]:
    out_deny = show_unauthentication(z, port, quiet=True)
    deny_ids = {d.onu_no for d in parse_unauthentication_blocks(out_deny)}
    out_pass = show_authentication(z, port, quiet=True)
    pass_ids = {p.onu_no for p in parse_authentication_blocks(out_pass)}
    total_ids = deny_ids.union(pass_ids)
    return (len(total_ids), len(pass_ids), len(deny_ids))

# ================== TYPE PICKER ==================
def get_available_onu_types(z: ZXAN) -> List[str]:
    out = get_running_config_cached(z)
    types: List[str] = []
    for line in out.splitlines():
        m = re.match(r"^\s*onu-type\s+(\S+)\s+epon\b", line, re.IGNORECASE)
        if m:
            types.append(m.group(1).strip())
    return sorted(set(types), key=lambda s: s.lower())

def normalize_model(model: Optional[str]) -> Optional[str]:
    if not model:
        return None
    m = model.strip()
    m = re.sub(r"\s+", "", m)
    m = re.sub(r"[^0-9a-zA-Z\-_]+", "", m)
    return m or None

def pick_type_from_model_strict(model: Optional[str], available_types: List[str]) -> Optional[str]:
    if not available_types:
        return None
    m = normalize_model(model)
    if not m:
        return None
    for t in available_types:
        if t.lower() == m.lower():
            return t
    contains = [t for t in available_types if m.lower() in t.lower()]
    if contains:
        contains.sort(key=lambda x: (len(x), x.lower()))
        return contains[0]
    suffix = [t for t in available_types if t.lower().endswith(m.lower())]
    if suffix:
        suffix.sort(key=lambda x: (len(x), x.lower()))
        return suffix[0]
    return None

# ================== ONU VLAN (service-port) ==================
def get_onu_service_ports(z: ZXAN, onu_if: str) -> Dict[int, int]:
    ensure_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg-onu-sp-read")
    z.send_wait_any(f"interface {onu_if}", 20, f"enter-{onu_if}")
    out = z.send_wait_any("show this", SHOW_TIMEOUT, f"show-this-{onu_if}")
    z.send_wait_any("exit", 20, f"exit-{onu_if}")
    ensure_exec(z)
    return parse_service_ports(out)

def set_onu_vlans(z: ZXAN, onu_if: str, vlans: List[int], mode: str = "APPEND"):
    mode = mode.upper().strip()
    target_vlans = uniq_int_list(vlans)
    if not target_vlans:
        return

    existing = get_onu_service_ports(z, onu_if)
    existing_vlans = set(existing.values())

    ensure_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg-onu-sp-write")
    z.send_wait_any(f"interface {onu_if}", 20, f"enter-{onu_if}")
    z.send_wait_any("switch mode hybrid", 20, f"hybrid-{onu_if}")

    if mode == "REPLACE":
        for sp_id in sorted(existing.keys()):
            z.send_wait_any(f"no service-port {sp_id}", 20, f"no-sp-{onu_if}-{sp_id}")
        for sp_id, vlan in enumerate(target_vlans, start=1):
            z.send_wait_any(f"service-port {sp_id} vport 1 user-vlan {vlan} vlan {vlan}", 30, f"sp-{onu_if}-{sp_id}")
    else:
        to_add = [v for v in target_vlans if v not in existing_vlans]
        next_id = (max(existing.keys()) + 1) if existing else 1
        for vlan in to_add:
            z.send_wait_any(f"service-port {next_id} vport 1 user-vlan {vlan} vlan {vlan}", 30, f"sp-{onu_if}-{next_id}")
            next_id += 1

    z.send_wait_any("exit", 20, f"exit-{onu_if}")
    ensure_exec(z)

# ================== SMART AUTO PROVISIONING ==================
def get_pass_list(z: ZXAN, olt_if: str) -> List[OnuPass]:
    out = show_authentication(z, olt_if, quiet=True)
    return parse_authentication_blocks(out)

def get_deny_list(z: ZXAN, olt_if: str) -> List[OnuDeny]:
    out = show_unauthentication(z, olt_if, quiet=True)
    return parse_unauthentication_blocks(out)

def fast_verify_mac_state(z: ZXAN, olt_if: str, mac: str) -> Tuple[bool, bool]:
    mac = mac.lower()
    t_end = time.time() + VERIFY_MAX_WAIT_SEC
    while True:
        denies = {d.mac.lower(): d for d in get_deny_list(z, olt_if) if d.mac}
        if mac not in denies:
            passed = get_pass_list(z, olt_if)
            ok_pass = any((p.mgmt_mac or "").lower() == mac for p in passed)
            return True, ok_pass
        if time.time() >= t_end:
            return False, False
        time.sleep(VERIFY_POLL_INTERVAL_SEC)

def rollback_onu_id(z: ZXAN, olt_if: str, onu_no: int, onu_prefix: str):
    try:
        enter_olt(z, olt_if)
        z.send_wait_any(f"no onu {onu_no}", 30, f"rollback-no-onu-{onu_no}")
        z.send_wait_any("exit", 10, "rollback-exit-olt-target")
        z.send_wait_any("exit", 10, "rollback-exit-olt-parent")
        z.send_wait_any("exit", 10, "rollback-exit-epon")
        ensure_exec(z)
    except Exception:
        pass

    onu_if = f"{onu_prefix}{onu_no}"
    try:
        ensure_exec(z)
        z.send_wait_any("configure terminal", 20, "rollback-cfg-onu")
        z.send_wait_any(f"interface {onu_if}", 20, f"rollback-enter-{onu_if}")
        z.send_wait_any("deregister", 20, f"rollback-deregister-{onu_if}")
        z.send_wait_any("deactivate", 20, f"rollback-deactivate-{onu_if}")
        z.send_wait_any("exit", 20, f"rollback-exit-{onu_if}")
        ensure_exec(z)
    except Exception:
        pass

def try_add_onu_with_type(z: ZXAN, olt_if: str, onu_no: int, onu_type: str, mac: str) -> Tuple[bool, str]:
    enter_olt(z, olt_if)
    out = z.send_wait_any(f"onu {onu_no} type {onu_type} mac {mac} ip-cfg static", 60, f"add-onu-{onu_no}-{onu_type}")
    z.send_wait_any("exit", 10, "exit-olt-target")
    z.send_wait_any("exit", 10, "exit-olt-parent")
    z.send_wait_any("exit", 10, "exit-epon")
    ensure_exec(z)
    return (not looks_like_error(out), out)

def apply_universal_onu_config(z: ZXAN, onu_if: str, vlans: List[int]):
    ensure_exec(z)
    z.send_wait_any("configure terminal", 10, "cfg-onu-template")
    z.send_wait_any(f"interface {onu_if}", 10, f"enter-{onu_if}")
    z.send_wait_any("switch mode hybrid", 10, f"hybrid-{onu_if}")
   
    for sp_id, vlan in enumerate(uniq_int_list(vlans), start=1):
        z.send_wait_any(f"service-port {sp_id} vport 1 user-vlan {vlan} vlan {vlan}", 30, f"sp-{onu_if}-{sp_id}")
    z.send_wait_any("exit", 20, f"exit-{onu_if}")
    ensure_exec(z)

@dataclass
class RenumItem:
    mac: str
    old_id: int
    new_id: int
    onu_type: str
    model: str
    state: str  # PASS/DENY

def build_port_sequential_plan(
    passed: List[OnuPass],
    denied: List[OnuDeny],
    available_types: List[str]
) -> List[RenumItem]:
    tmp: List[Tuple[int, RenumItem]] = []

    for p in passed:
        mac = (p.mgmt_mac or "").lower()
        if not mac:
            continue
        t = (p.onu_type or "").strip()
        if not t:
            raise RuntimeError(f"TYPE kosong untuk PASS ONU {p.onu_no} mac={mac}")
        tmp.append((p.onu_no, RenumItem(mac=mac, old_id=p.onu_no, new_id=0, onu_type=t, model="-", state="PASS")))

    for d in denied:
        mac = (d.mac or "").lower()
        if not mac:
            continue
        model = d.model or "-"
        t = pick_type_from_model_strict(model, available_types)
        if (not t) and DEFAULT_ONU_TYPE:
            if any(x.lower() == DEFAULT_ONU_TYPE.lower() for x in available_types):
                t = next(x for x in available_types if x.lower() == DEFAULT_ONU_TYPE.lower())
        if not t:
            raise RuntimeError(f"TYPE tidak ditemukan untuk DENY mac={mac} model={model}")
        tmp.append((d.onu_no, RenumItem(mac=mac, old_id=d.onu_no, new_id=0, onu_type=t, model=model, state="DENY")))

    tmp.sort(key=lambda x: x[0])

    plan: List[RenumItem] = []
    new_id = START_ONU_ID
    for _, item in tmp:
        item.new_id = new_id
        plan.append(item)
        new_id += 1
        if new_id > MAX_ONU_ID + 1:
            raise RuntimeError(f"ONU ID melebihi range {START_ONU_ID}..{MAX_ONU_ID}")
    return plan

def apply_plan_sequential_port(z: ZXAN, olt_if: str, onu_prefix: str, plan: List[RenumItem], prov_vlans: List[int]) -> Tuple[int, int]:
    ok = 0
    total = len(plan)
    for it in plan:
        onu_if_new = f"{onu_prefix}{it.new_id}"
        print(f" - [{it.state}] {it.mac} | {it.onu_type} | OLD {it.old_id} -> NEW {it.new_id}")

        rollback_onu_id(z, olt_if, it.old_id, onu_prefix)
        if it.new_id != it.old_id:
            rollback_onu_id(z, olt_if, it.new_id, onu_prefix)

        ok_add, add_out = try_add_onu_with_type(z, olt_if, it.new_id, it.onu_type, it.mac)
        if not ok_add:
            print(f"   -> ADD GAGAL: {it.mac} new_id={it.new_id}")
            print(extract_error_snippet(add_out))
            continue

        apply_universal_onu_config(z, onu_if_new, prov_vlans)

        cleared, _ = fast_verify_mac_state(z, olt_if, it.mac)
        if cleared:
            ok += 1
            wr_after_each(z, note=f"{onu_if_new}")
        else:
            print(f"   -> BELUM STABLE: {it.mac}")
    return ok, total

# ================== SEARCH MAC (SEMUA PORT) ==================
def search_macs_on_port(z: ZXAN, port: str, queries: List[str]) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    out_deny = show_unauthentication(z, port, quiet=True)
    denies = parse_unauthentication_blocks(out_deny)
    for d in denies:
        fm = (d.mac or "").lower()
        if not fm:
            continue
        for q in queries:
            if mac_match(fm, q):
                results.append({"query": q, "mac": fm, "status": "DENY", "port": port, "onu_id": str(d.onu_no),
                                "type": "-", "model": d.model or "-"})
                break

    out_pass = show_authentication(z, port, quiet=True)
    passed = parse_authentication_blocks(out_pass)
    for p in passed:
        fm = (p.mgmt_mac or "").lower()
        if not fm:
            continue
        for q in queries:
            if mac_match(fm, q):
                results.append({"query": q, "mac": fm, "status": "PASS", "port": port, "onu_id": str(p.onu_no),
                                "type": p.onu_type or "-", "model": "-"})
                break
    return results

def search_macs_all_ports(z: ZXAN, queries: List[str]) -> List[Dict[str, str]]:
    all_results: List[Dict[str, str]] = []
    with silent(z.log):
        roots = discover_root_cards_from_help(z)
        ports: List[str] = []
        for r0 in roots:
            ports.extend(expand_ports_from_root(r0, ports_per_card=8))
    for p in ports:
        res = search_macs_on_port(z, p, queries)
        if res:
            all_results.extend(res)

    def keyfn(x):
        try:
            onu = int(x.get("onu_id", "0"))
        except Exception:
            onu = 0
        return (x.get("query", ""), x.get("port", ""), onu, x.get("mac", ""))
    all_results.sort(key=keyfn)
    return all_results

def print_search_results(queries: List[str], results: List[Dict[str, str]]):
    print("\n=== HASIL SEARCH MAC (SEMUA PORT) ===")
    if not results:
        for q in queries:
            print(f"\n[QUERY {q}] NOT FOUND")
        return
    byq: Dict[str, List[Dict[str, str]]] = {}
    for r in results:
        byq.setdefault(r["query"], []).append(r)
    for q in queries:
        rows = byq.get(q, [])
        if not rows:
            print(f"\n[QUERY {q}] NOT FOUND")
            continue
        print(f"\n[QUERY {q}] FOUND {len(rows)}")
        for r in rows:
            print(f"- MAC {r['mac']} | {r['status']} | PORT {r['port']} | ONU_ID {r['onu_id']} | TYPE {r['type']} | MODEL {r['model']}")

# ================== DELETE ALL ONU (PORT) ==================
def get_all_onu_ids_on_port(z: ZXAN, olt_if: str) -> List[int]:
    out_deny = show_unauthentication(z, olt_if, quiet=True)
    deny_ids = {d.onu_no for d in parse_unauthentication_blocks(out_deny)}
    out_pass = show_authentication(z, olt_if, quiet=True)
    pass_ids = {p.onu_no for p in parse_authentication_blocks(out_pass)}
    return sorted(deny_ids.union(pass_ids))

def delete_onu_ids(z: ZXAN, olt_if: str, ids: List[int]):
    if not ids:
        return
    enter_olt(z, olt_if)
    for onu_no in ids:
        z.send_wait_any(f"no onu {onu_no}", 30, f"no-onu-{onu_no}")
    z.send_wait_any("exit", 10, "exit-olt-target")
    z.send_wait_any("exit", 10, "exit-olt-parent")
    z.send_wait_any("exit", 10, "exit-epon")
    ensure_exec(z)

# ================== REBOOT ONU ==================
def reboot_onu(z: ZXAN, onu_if: str) -> bool:
    onu_if = onu_if.strip()
    if not onu_if:
        return False
    ensure_exec(z)
    z.send_wait_any("configure terminal", 20, "reboot-cfg")
    z.send_wait_any("pon-onu", 20, "reboot-pon-onu")
    z.send_wait_any(f"pon-onu-mng {onu_if}", 20, f"reboot-mng-{onu_if}")
    out = z.send_wait_any("reboot", 60, f"reboot-{onu_if}")
    z.send_wait_any("exit", 20, f"reboot-exit-mng-{onu_if}")
    z.send_wait_any("exit", 20, f"reboot-exit-pon-onu-{onu_if}")
    ensure_exec(z)
    if looks_like_error(out):
        print(f"   -> REBOOT GAGAL: {onu_if}")
        print(extract_error_snippet(out))
        return False
    print(f"   -> REBOOT OK: {onu_if}")
    return True

def reboot_by_ids_on_current_port(z: ZXAN, onu_prefix: str, ids: List[int]):
    ids = uniq_int_list(ids)
    if not ids:
        print("Tidak ada ONU ID.")
        return
    print(f"Reboot ONU IDs (port aktif): {ids}")
    confirm = input("Ketik YES untuk lanjut reboot: ").strip()
    if confirm != "YES":
        print("Batal.")
        return
    ok = 0
    for onu_no in ids:
        onu_if = f"{onu_prefix}{onu_no}"
        if reboot_onu(z, onu_if):
            ok += 1
        time.sleep(0.2)
    print(f"Selesai reboot by ID. OK={ok}/{len(ids)}")

def reboot_all_on_current_port(z: ZXAN, olt_if: str, onu_prefix: str):
    ids = get_all_onu_ids_on_port(z, olt_if)
    if not ids:
        print("Tidak ada ONU di port ini (PASS/DENY).")
        return
    print(f"Reboot SEMUA ONU di port ini: total={len(ids)} | IDs={ids}")
    confirm = input("Ketik REBOOTALL untuk lanjut: ").strip()
    if confirm != "REBOOTALL":
        print("Batal.")
        return
    ok = 0
    for onu_no in ids:
        onu_if = f"{onu_prefix}{onu_no}"
        if reboot_onu(z, onu_if):
            ok += 1
        time.sleep(0.2)
    print(f"Selesai reboot all port. OK={ok}/{len(ids)}")

def reboot_all_on_current_card(z: ZXAN, current_olt_if: str):
    root = olt_root_from_port(current_olt_if)
    if not root:
        print("Gagal deteksi root card dari port aktif.")
        return
    ports = [f"{root}/{i}" for i in range(1, 9)]
    port_map: Dict[str, Tuple[str, List[int]]] = {}
    total = 0
    for p in ports:
        pref = onu_prefix_from_olt_port(p) or ""
        ids = get_all_onu_ids_on_port(z, p)
        if ids:
            port_map[p] = (pref, ids)
            total += len(ids)
    if total == 0:
        print("Tidak ada ONU terdeteksi pada card ini (semua port kosong).")
        return
    print("\nReboot SEMUA ONU di CARD ini:")
    for p, (_, ids) in port_map.items():
        print(f" - {p}: total={len(ids)} | IDs={ids}")
    confirm = input(f"Ketik REBOOTCARD untuk lanjut reboot total {total} ONU: ").strip()
    if confirm != "REBOOTCARD":
        print("Batal.")
        return
    ok = done = 0
    for p, (pref, ids) in port_map.items():
        print(f"\n[PORT {p}] reboot {len(ids)} ONU ...")
        for onu_no in ids:
            onu_if = f"{pref}{onu_no}"
            if reboot_onu(z, onu_if):
                ok += 1
            done += 1
            time.sleep(0.2)
    print(f"\nSelesai reboot card. OK={ok}/{done}")

# ================== PRINT CARD (2 tahap) ==================
def print_card_quick(z: ZXAN, current_olt_if: str):
    root = olt_root_from_port(current_olt_if)
    if not root:
        print("Gagal deteksi root card.")
        return {}, {}
    ports = [f"{root}/{i}" for i in range(1, 9)]
    all_pass: Dict[str, List[OnuPass]] = {}
    all_prefix: Dict[str, str] = {}
    for port in ports:
        out_pass = show_authentication(z, port, quiet=True)
        passed = parse_authentication_blocks(out_pass)
        out_deny = show_unauthentication(z, port, quiet=True)
        denies = parse_unauthentication_blocks(out_deny)
        total = len(passed) + len(denies)
        if total == 0:
            continue
        pref = onu_prefix_from_olt_port(port) or ""
        all_prefix[port] = pref
        all_pass[port] = passed
        print(f"\n--- PORT {port} | PASS {len(passed)} | DENY {len(denies)} ---")
        if passed:
            print("PASS:")
            for p in passed:
                print(f" - ONU {p.onu_no} | TYPE {p.onu_type or '-'} | MgmtMAC {p.mgmt_mac or '-'} | LastAuth {p.last_auth_time or '-'}")
        if denies:
            print("DENY:")
            for d in denies:
                print(f" - ONU {d.onu_no} | MAC {d.mac or '-'} | MODEL {d.model or '-'}")
    return all_pass, all_prefix

def print_card_optic(z: ZXAN, all_pass: Dict[str, List[OnuPass]], all_prefix: Dict[str, str]):
    print("\n=== AMBIL TX/RX (akan lebih lambat) ===")
    for port, passed in all_pass.items():
        if not passed:
            continue
        pref = all_prefix.get(port, "")
        print(f"\n--- PORT {port} | PASS {len(passed)} (TX/RX) ---")
        for p in passed:
            onu_if = f"{pref}{p.onu_no}"
            optic = get_onu_optic_cached(z, onu_if)
            tx = f"{optic.onu_tx_up_dbm:.3f} dBm" if optic.onu_tx_up_dbm is not None else "-"
            rx = f"{optic.onu_rx_down_dbm:.3f} dBm" if optic.onu_rx_down_dbm is not None else "-"
            print(f" - ONU {p.onu_no} | TYPE {p.onu_type or '-'} | TX {tx} | RX {rx}")

# ================== MODE TYPE (menu 13) ==================
def add_onu_type_epon(z: ZXAN, onu_type: str, eth_ports: int, wifi_ssids: int, voip_ports: int):
    onu_type = onu_type.strip()
    if not onu_type:
        raise ValueError("ONU type kosong")
    eth_ports = max(0, int(eth_ports))
    wifi_ssids = max(0, int(wifi_ssids))
    voip_ports = max(0, int(voip_ports))

    enter_config(z)
    z.send_wait_any("pon", 20, "enter-pon")
    z.send_wait_any(f"onu-type {onu_type} epon", 20, f"onu-type-{onu_type}")
    for i in range(1, eth_ports + 1):
        z.send_wait_any(f"onu-type-if {onu_type} eth_0/{i}", 20, f"typeif-eth-{onu_type}-{i}")
    for i in range(1, wifi_ssids + 1):
        z.send_wait_any(f"onu-type-if {onu_type} wifi_0/{i}", 20, f"typeif-wifi-{onu_type}-{i}")
    for i in range(1, voip_ports + 1):
        z.send_wait_any(f"onu-type-if {onu_type} pots_0/{i}", 20, f"typeif-pots-{onu_type}-{i}")
    z.send_wait_any("exit", 20, "exit-pon")
    ensure_exec(z)
    wr_after_each(z, note=f"ADD TYPE {onu_type}")

def mode_type_menu(z: ZXAN, olt_if: str, available_types: List[str]) -> List[str]:
    global DEFAULT_ONU_TYPE
    while True:
        print("\n=== MODE 13: TYPE ===")
        print(f"DEFAULT TYPE (fallback) = {DEFAULT_ONU_TYPE or '(DISABLED)'}")
        print("1) Set DEFAULT TYPE (fallback) [kosongkan untuk disable]")
        print("2) Show TYPE ONU PASS (di port aktif)")
        print("3) Delete ONU PASS by TYPE (no onu) + WR")
        print("4) Tambah ONU TYPE (register type + port map) + WR")
        print("0) Kembali")
        ch = input("Pilih: ").strip()

        if ch == "0":
            return available_types

        if ch == "1":
            t = input("Masukkan TYPE fallback baru (kosong=disable): ").strip()
            DEFAULT_ONU_TYPE = t
            print(f"OK. DEFAULT TYPE sekarang: {DEFAULT_ONU_TYPE or '(DISABLED)'}")
            continue

        if ch == "2":
            out_pass = show_authentication(z, olt_if, quiet=True)
            passed = parse_authentication_blocks(out_pass)
            if not passed:
                print("Tidak ada PASS di port ini.")
                continue
            cnt: Dict[str, int] = {}
            print(f"\nPASS count={len(passed)}")
            for p in passed:
                typ = p.onu_type or "-"
                cnt[typ] = cnt.get(typ, 0) + 1
                print(f" - ONU {p.onu_no} | TYPE {typ} | MgmtMAC {p.mgmt_mac or '-'} | LastAuth {p.last_auth_time or '-'}")
            print("\nSUMMARY TYPE:")
            for k in sorted(cnt.keys()):
                print(f" - {k}: {cnt[k]}")
            continue

        if ch == "3":
            target = input("Masukkan TYPE yang mau dihapus: ").strip()
            if not target:
                print("TYPE kosong.")
                continue
            out_pass = show_authentication(z, olt_if, quiet=True)
            passed = parse_authentication_blocks(out_pass)
            to_del = [p.onu_no for p in passed if (p.onu_type or "").lower() == target.lower()]
            if not to_del:
                print(f"Tidak ada ONU PASS dengan TYPE '{target}'.")
                continue
            print(f"Akan delete ONU ID: {to_del}")
            confirm = input("Ketik YES untuk lanjut delete: ").strip()
            if confirm != "YES":
                print("Batal.")
                continue
            delete_onu_ids(z, olt_if, to_del)
            wr_after_each(z, note=f"DEL TYPE {target}")
            print("Delete by TYPE selesai + WR.")
            continue

        if ch == "4":
            onu_type = input("Masukkan ONU TYPE baru: ").strip()
            if not onu_type:
                print("TYPE kosong.")
                continue
            try:
                eth_ports = int(input("Jumlah Ethernet ports: ").strip() or "0")
                wifi_ssids = int(input("Jumlah WiFi SSIDs: ").strip() or "0")
                voip_ports = int(input("Jumlah VoIP ports: ").strip() or "0")
            except Exception:
                print("Input angka tidak valid.")
                continue
            confirm = input("Ketik YES untuk lanjut: ").strip()
            if confirm != "YES":
                print("Batal.")
                continue
            add_onu_type_epon(z, onu_type, eth_ports, wifi_ssids, voip_ports)
            print("Refresh daftar TYPE...")
            available_types = get_available_onu_types(z)
            continue

        print("Pilihan tidak dikenal.")

# ================== UPDATE VLAN PASS DI CARD (menu 18) ==================
def get_pass_ids_on_port(z: ZXAN, port: str) -> List[int]:
    out = show_authentication(z, port, quiet=True)
    passed = parse_authentication_blocks(out)
    ids = [p.onu_no for p in passed]
    return sorted(set(ids))

def update_vlan_all_pass_on_card(z: ZXAN, current_olt_if: str, vlans: List[int], mode: str):
    root = olt_root_from_port(current_olt_if)
    if not root:
        print("Gagal deteksi root card dari port aktif.")
        return

    ports = [f"{root}/{i}" for i in range(1, 9)]
    total = 0
    targets: List[Tuple[str, str, List[int]]] = []
    for p in ports:
        pref = onu_prefix_from_olt_port(p) or ""
        ids = get_pass_ids_on_port(z, p)
        if ids:
            targets.append((p, pref, ids))
            total += len(ids)

    if total == 0:
        print("Tidak ada ONU PASS pada card ini.")
        return

    print("\n=== UPDATE VLAN SEMUA ONU PASS DI CARD AKTIF ===")
    print(f"Root: {root}")
    print(f"Mode: {mode} | VLAN: {uniq_int_list(vlans)}")
    for p, _, ids in targets:
        print(f" - {p}: PASS {len(ids)}")

    confirm = input("Ketik UPDATEPASSCARD untuk lanjut: ").strip()
    if confirm != "UPDATEPASSCARD":
        print("Batal.")
        return

    done = ok = 0
    for p, pref, ids in targets:
        print(f"\n[PORT {p}] update VLAN PASS {len(ids)} ONU ...")
        for onu_no in ids:
            onu_if = f"{pref}{onu_no}"
            print(f" - {onu_if} => {mode} {uniq_int_list(vlans)}")
            try:
                set_onu_vlans(z, onu_if, vlans, mode=mode)
                wr_after_each(z, note=f"VLAN {onu_if}")
                ok += 1
            except Exception as e:
                print(f"   -> GAGAL: {onu_if} | {e}")
            done += 1
    print(f"\nSelesai UPDATEPASSCARD VLAN. OK={ok}/{done}")

# ================== UPLINK VLAN MANAGER (menu 19) ==================
def show_interface_this(z: ZXAN, ifname: str) -> str:
    ifname = ifname.strip()
    if not ifname:
        return ""
    ensure_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg-if-show")
    z.send_wait_any(f"interface {ifname}", 20, f"enter-if-{ifname}")
    out = z.send_wait_any("show this", SHOW_TIMEOUT, f"show-this-{ifname}")
    z.send_wait_any("exit", 20, f"exit-if-{ifname}")
    ensure_exec(z)
    return out

def parse_switchport_vlan_lines(text: str) -> Dict[str, Set[int]]:
    res = {"tag": set(), "untag": set()}
    for line in text.splitlines():
        m = re.search(r"switchport\s+vlan\s+([0-9,\-\s]+)\s+(tag|untag)\b", line, re.IGNORECASE)
        if not m:
            continue
        rng = m.group(1).strip().replace(" ", "")
        mode = m.group(2).lower()
        res.setdefault(mode, set()).update(parse_csv_ints(rng))
    return res

def apply_switchport_vlan_update(
    z: ZXAN,
    ifname: str,
    vlans: List[int],
    action: str = "APPEND",
    tagmode: str = "tag"
):
    action = action.upper().strip()
    tagmode = tagmode.lower().strip()
    if tagmode not in ("tag", "untag"):
        raise ValueError("tagmode harus 'tag' atau 'untag'")

    target = uniq_int_list(vlans)
    if not target:
        print("VLAN kosong.")
        return

    out_this = show_interface_this(z, ifname)
    existing = parse_switchport_vlan_lines(out_this).get(tagmode, set())

    ensure_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg-if-vlan")
    z.send_wait_any(f"interface {ifname}", 20, f"enter-if-{ifname}")

    def run(cmd: str, label: str, t: int = 30) -> str:
        return z.send_wait_any(cmd, t, label)

    if action == "APPEND":
        to_add = [v for v in target if v not in existing]
        if not to_add:
            print("Tidak ada VLAN baru untuk ditambahkan (sudah ada).")
        else:
            for rng in chunk_vlan_cmd_ranges(to_add):
                out = run(f"switchport vlan {rng} {tagmode}", f"if-add-{ifname}-{tagmode}")
                if looks_like_error(out):
                    print("   -> ERROR tambah VLAN:")
                    print(extract_error_snippet(out))

    elif action == "REMOVE":
        to_del = [v for v in target if v in existing]
        if not to_del:
            print("Tidak ada VLAN yang cocok untuk dihapus (tidak ditemukan di interface).")
        else:
            for rng in chunk_vlan_cmd_ranges(to_del):
                out = run(f"no switchport vlan {rng} {tagmode}", f"if-del-{ifname}-{tagmode}")
                if looks_like_error(out):
                    print("   -> ERROR hapus VLAN:")
                    print(extract_error_snippet(out))

    elif action == "REPLACE":
        if existing:
            out = run(f"no switchport vlan all {tagmode}", f"if-clear-all-{ifname}-{tagmode}")
            if looks_like_error(out):
                for rng in chunk_vlan_cmd_ranges(sorted(existing)):
                    out2 = run(f"no switchport vlan {rng} {tagmode}", f"if-clear-{ifname}-{tagmode}")
                    if looks_like_error(out2):
                        print("   -> ERROR clear VLAN (fallback):")
                        print(extract_error_snippet(out2))

        for rng in chunk_vlan_cmd_ranges(target):
            out = run(f"switchport vlan {rng} {tagmode}", f"if-replace-add-{ifname}-{tagmode}")
            if looks_like_error(out):
                print("   -> ERROR replace add VLAN:")
                print(extract_error_snippet(out))

    else:
        z.send_wait_any("exit", 20, f"exit-if-{ifname}")
        ensure_exec(z)
        raise ValueError("action harus APPEND/REMOVE/REPLACE")

    z.send_wait_any("exit", 20, f"exit-if-{ifname}")
    ensure_exec(z)

def list_uplink_interfaces_from_runningcfg(runcfg: str) -> List[str]:
    ifnames = []
    for line in runcfg.splitlines():
        m = re.match(r"^\s*interface\s+(\S+)\s*$", line, re.IGNORECASE)
        if not m:
            continue
        name = m.group(1).strip()
        if re.match(r"^(xgei_|gei_|xe|xg|gi|g|eth)\b", name, re.IGNORECASE):
            ifnames.append(name)
    seen = set()
    out = []
    for n in ifnames:
        k = n.lower()
        if k not in seen:
            out.append(n)
            seen.add(k)
    return out

def menu_uplink_vlan(z: ZXAN):
    runcfg = get_running_config_cached(z)
    ifs = list_uplink_interfaces_from_runningcfg(runcfg)
    print("\n=== UPLINK INTERFACE LIST (sample) ===")
    if ifs:
        for n in ifs[:25]:
            print(f" - {n}")
        if len(ifs) > 25:
            print(f" ... (+{len(ifs)-25} lainnya)")
    else:
        print("Tidak ada interface uplink terdeteksi (boleh input manual).")

    ifname = input("\nMasukkan interface (cth: xgei_1/20/2): ").strip()
    if not ifname:
        print("Batal.")
        return

    while True:
        print(f"\n=== VLAN TAG MANAGER: {ifname} ===")
        print("1) Show config interface (show this)")
        print("2) APPEND VLAN (tag/untag)")
        print("3) REMOVE VLAN (tag/untag)")
        print("4) REPLACE VLAN (tag/untag)")
        print("0) Kembali")
        ch = input("Pilih: ").strip()

        if ch == "0":
            return

        if ch == "1":
            out = show_interface_this(z, ifname)
            print("\n--- SHOW THIS ---")
            print(out)
            parsed = parse_switchport_vlan_lines(out)
            print("\n--- PARSED VLAN ---")
            print(f"TAG  : {compress_ranges(sorted(parsed.get('tag', set())))}")
            print(f"UNTAG: {compress_ranges(sorted(parsed.get('untag', set())))}")
            continue

        if ch in ("2", "3", "4"):
            vlan_s = input("Masukkan VLAN (cth 1,18,39,52,111-255): ").strip()
            vlans = parse_csv_ints(vlan_s)
            if not vlans:
                print("VLAN kosong.")
                continue
            tagmode = input("Mode tag atau untag? [tag/untag] (default=tag): ").strip().lower() or "tag"
            action = {"2": "APPEND", "3": "REMOVE", "4": "REPLACE"}[ch]

            print(f"\nTARGET: if={ifname} action={action} {tagmode} vlans={compress_ranges(vlans)}")
            confirm = input("Ketik YES untuk lanjut: ").strip()
            if confirm != "YES":
                print("Batal.")
                continue

            apply_switchport_vlan_update(z, ifname, vlans, action=action, tagmode=tagmode)
            wr_after_each(z, note=f"IF {ifname} {action} {tagmode}")
            print("Selesai + WR.")
            continue

        print("Pilihan tidak dikenal.")

# ================== VLAN DATABASE MANAGER (menu 20) ==================
def parse_vlan_database_from_runningcfg(runcfg: str) -> Set[int]:
    vlans: Set[int] = set()
    lines = runcfg.splitlines()
    in_db = False
    for ln in lines:
        if re.match(r"^\s*vlan\s+database\s*$", ln, re.IGNORECASE):
            in_db = True
            continue
        if in_db:
            if re.match(r"^\S", ln):
                break
            mm = re.search(r"^\s*vlan\s+([0-9,\-\s]+)\s*$", ln, re.IGNORECASE)
            if mm:
                vlans.update(parse_csv_ints(mm.group(1).replace(" ", "")))
    return vlans

def apply_vlan_database_update(z: ZXAN, vlans: List[int], action: str = "ADD"):
    action = action.upper().strip()
    target = uniq_int_list(vlans)
    if not target:
        print("VLAN kosong.")
        return

    ensure_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg-vlan-db")
    z.send_wait_any("vlan database", 20, "enter-vlan-db")

    if action == "ADD":
        for rng in chunk_vlan_cmd_ranges(target):
            out = z.send_wait_any(f"vlan {rng}", 30, f"vlan-db-add-{rng}")
            if looks_like_error(out):
                print("   -> ERROR add vlan db:")
                print(extract_error_snippet(out))
    elif action == "REMOVE":
        for rng in chunk_vlan_cmd_ranges(target):
            out = z.send_wait_any(f"no vlan {rng}", 30, f"vlan-db-del-{rng}")
            if looks_like_error(out):
                print("   -> ERROR del vlan db:")
                print(extract_error_snippet(out))
    else:
        z.send_wait_any("exit", 20, "exit-vlan-db")
        ensure_exec(z)
        raise ValueError("action harus ADD/REMOVE")

    z.send_wait_any("exit", 20, "exit-vlan-db")
    ensure_exec(z)

def extract_all_referenced_vlans_from_runningcfg(runcfg: str) -> Set[int]:
    v: Set[int] = set(PROV_VLANS)

    for m in re.finditer(r"switchport\s+vlan\s+([0-9,\-\s]+)\s+(?:tag|untag)\b", runcfg, re.IGNORECASE):
        rng = m.group(1).replace(" ", "")
        v.update(parse_csv_ints(rng))

    for m in re.finditer(r"\bservice-port\s+\d+.*?\bvlan\s+(\d+)\b", runcfg, re.IGNORECASE):
        try:
            v.add(int(m.group(1)))
        except Exception:
            pass

    return {x for x in v if 1 <= int(x) <= 4094}

def vlan_db_autosync(z: ZXAN):
    runcfg = get_running_config_cached(z, force=True)
    db_now = parse_vlan_database_from_runningcfg(runcfg)
    need = extract_all_referenced_vlans_from_runningcfg(runcfg)
    missing = sorted(need - db_now)

    print("\n=== VLAN DB AUTO-SYNC ===")
    print(f"Need: {len(need)} | InDB: {len(db_now)} | Missing: {len(missing)}")
    if not missing:
        print("Sudah sinkron.")
        return

    confirm = input("Ketik SYNC untuk tambah VLAN missing ke VLAN database: ").strip()
    if confirm != "SYNC":
        print("Batal.")
        return

    apply_vlan_database_update(z, missing, action="ADD")
    wr_after_each(z, note="VLANDB AUTOSYNC")
    print("AUTO-SYNC selesai + WR.")

def menu_vlan_database(z: ZXAN):
    runcfg = get_running_config_cached(z, force=True)
    db = parse_vlan_database_from_runningcfg(runcfg)
    print("\n=== VLAN DATABASE (parsed) ===")
    if db:
        rr = compress_ranges(sorted(db))
        print(f"Total VLAN di DB: {len(db)}")
        print(f"Range: {rr[:200]}{' ...' if len(rr)>200 else ''}")
    else:
        print("VLAN database tidak ter-parse (atau kosong).")

    while True:
        print("\n=== VLAN DATABASE MENU ===")
        print("1) ADD VLAN ke VLAN database")
        print("2) REMOVE VLAN dari VLAN database")
        print("3) AUTO-SYNC VLAN database + WR")
        print("4) Refresh tampilkan VLAN database")
        print("0) Kembali")
        ch = input("Pilih: ").strip()

        if ch == "0":
            return

        if ch == "4":
            runcfg = get_running_config_cached(z, force=True)
            db = parse_vlan_database_from_runningcfg(runcfg)
            print("\n=== VLAN DATABASE (parsed) ===")
            if db:
                rr = compress_ranges(sorted(db))
                print(f"Total VLAN di DB: {len(db)}")
                print(f"Range: {rr[:200]}{' ...' if len(rr)>200 else ''}")
            else:
                print("VLAN database tidak ter-parse (atau kosong).")
            continue

        if ch == "3":
            vlan_db_autosync(z)
            continue

        if ch in ("1", "2"):
            vlan_s = input("Masukkan VLAN (cth 52 / 1,18,52,111-255): ").strip()
            vlans = parse_csv_ints(vlan_s)
            if not vlans:
                print("VLAN kosong.")
                continue
            action = "ADD" if ch == "1" else "REMOVE"
            confirm = input(f"Ketik YES untuk {action} VLANDB {compress_ranges(vlans)}: ").strip()
            if confirm != "YES":
                print("Batal.")
                continue
            apply_vlan_database_update(z, vlans, action=action)
            wr_after_each(z, note=f"VLANDB {action}")
            print("Selesai + WR.")
            continue

        print("Pilihan tidak dikenal.")

# ================== VLAN TEMPLATE INPUT (SETELAH LOGIN) ==================
def ask_prov_vlans_after_login() -> List[int]:
    print("\n=== INPUT VLAN TEMPLATE PROVISIONING (setelah LOGIN) ===")
    print("Contoh: 1,18,39,52,111-255")
    print("ENTER saja = pakai DEFAULT_VLANS lama")
    s = input("Masukkan VLAN template provisioning: ").strip()
    if not s:
        return DEFAULT_VLANS.copy()
    vl = parse_csv_ints(s)
    if not vl:
        print("Input VLAN tidak valid, fallback ke DEFAULT_VLANS.")
        return DEFAULT_VLANS.copy()
    return uniq_int_list(vl)

# ================== MENU UI ==================
def menu():
    print("\n=== MENU ===")
    print("PROV_VLANS aktif:", compress_ranges(PROV_VLANS))
    print("1) List ONU UNAUTH (deny) + MAC/MODEL      [CLEAR SCREEN]")
    print("2) AUTH PASS (2 tahap: cepat -> ENTER TX/RX) [CLEAR SCREEN]")
    print("3) Search ONU by MAC (SEMUA PORT) [FULL/PREFIX MAC]")
    print("5) SMART AUTO PROVISIONING: RENUNBER+AUTO PROVISION (PASS+DENY) -> 1..N + APPLY PROV_VLANS + WR")
    print("6) Ganti interface (port OLT)")
    print("9) Count ONU terdaftar di SEMUA card/port")
    print("13) MODE TYPE (fallback / show / delete / tambah onu-type)")
    print("14) Edit VLAN ONU (APPEND/REPLACE) + WR per ONU")
    print("15) DELETE ALL ONU di port ini + WR")
    print("16) PRINT ONU di CARD aktif (2 tahap: cepat -> ENTER TX/RX)")
    print("17) REBOOT ONU (by ID / all port / all card)")
    print("18) UPDATE VLAN SEMUA ONU PASS DI CARD AKTIF (CUSTOM VLAN) + WR")
    print("19) UPLINK VLAN TAG MANAGER (XGE/GE) + WR")
    print("20) VLAN DATABASE MANAGER + AUTO-SYNC + WR")
    print("21) Set PROV_VLANS (ubah VLAN template provisioning)")
    print("0) Keluar")

# ================== MAIN ==================
def main():
    global PROV_VLANS

    log_file = f"zxan_menu_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log = Logger(log_file)

    olt_if = input("Masukkan interface EPON OLT (contoh: epon-olt_1/4/3): ").strip()
    m = re.search(r"epon-olt_(\d+/\d+/\d+)", olt_if, re.IGNORECASE)
    if not m:
        print("Format salah. Contoh: epon-olt_1/4/3")
        return
    onu_prefix = f"epon-onu_{m.group(1)}:"

    z = ZXAN(HOST, PORT, log)
    try:
        z.login_fast(USERNAME, PASSWORD)

        ensure_exec(z)
        z.send_wait_any("terminal length 0", 10, "paging-length0")
        z.send_wait_any("terminal page 0", 10, "paging-page0")
        ensure_exec(z)

        PROV_VLANS = ask_prov_vlans_after_login()
        print("PROV_VLANS aktif:", compress_ranges(PROV_VLANS))

        try:
            enter_olt(z, olt_if)
            z.send_wait_any("exit", 10, "exit-olt-target")
            z.send_wait_any("exit", 10, "exit-olt-parent")
            z.send_wait_any("exit", 10, "exit-epon")
            ensure_exec(z)
        except Exception:
            ensure_exec(z)

        available_types: List[str] = []

        while True:
            menu()
            c = input(f"[{olt_if}] Pilih: ").strip()

            if c == "0":
                break

            if c == "6":
                olt_if_new = input("Masukkan interface baru (cth: epon-olt_1/4/3): ").strip()
                m2 = re.search(r"epon-olt_(\d+/\d+/\d+)", olt_if_new, re.IGNORECASE)
                if not m2:
                    print("Format salah.")
                    continue
                olt_if = olt_if_new
                onu_prefix = f"epon-onu_{m2.group(1)}:"
                print(f"OK. Interface aktif sekarang: {olt_if}")
                continue

            if c == "21":
                PROV_VLANS = ask_prov_vlans_after_login()
                print("PROV_VLANS aktif:", compress_ranges(PROV_VLANS))
                continue

            if c == "1":
                clear_screen()
                out = show_unauthentication(z, olt_if, quiet=True)
                deny = parse_unauthentication_blocks(out)
                print(f"\nAUTH DENY: {len(deny)} ONU")
                for d in deny:
                    print(f" - ONU {d.onu_no} | MAC {d.mac or '-'} | MODEL {d.model or '-'}")
                continue

            if c == "2":
                clear_screen()
                out_pass = show_authentication(z, olt_if, quiet=True)
                passed = parse_authentication_blocks(out_pass)
                print(f"\nAUTH PASS: {len(passed)} ONU")
                for p in passed:
                    print(f" - ONU {p.onu_no} | TYPE {p.onu_type or '-'} | MgmtMAC {p.mgmt_mac or '-'} | LastAuth {p.last_auth_time or '-'}")
                choice = input("\nTekan ENTER untuk ambil TX/RX (atau ketik SKIP): ").strip().upper()
                if choice == "":
                    print("\n=== TX/RX (akan lebih lambat) ===")
                    for p in passed:
                        onu_if = f"{onu_prefix}{p.onu_no}"
                        optic = get_onu_optic_cached(z, onu_if)
                        tx = f"{optic.onu_tx_up_dbm:.3f} dBm" if optic.onu_tx_up_dbm is not None else "-"
                        rx = f"{optic.onu_rx_down_dbm:.3f} dBm" if optic.onu_rx_down_dbm is not None else "-"
                        print(f" - ONU {p.onu_no} | TYPE {p.onu_type or '-'} | TX {tx} | RX {rx}")
                continue

            if c == "3":
                raw = input("Masukkan MAC / PREFIX (boleh banyak, pisah koma/spasi):\n> ").strip()
                queries = parse_mac_inputs(raw)
                if not queries:
                    print("Input kosong / format salah.")
                    continue
                print("Scan SEMUA port... (bisa agak lama)")
                results = search_macs_all_ports(z, queries)
                print_search_results(queries, results)
                continue

            if c == "5":
                if not available_types:
                    available_types = get_available_onu_types(z)

                print("\n=== SMART AUTO PROVISIONING (RENUNBER + AUTO PROVISION) ===")
                print("WAJIB: ONU ID port ini akan jadi 1..N berurutan (PASS+DENY).")
                print("APPLY VLAN TEMPLATE:", compress_ranges(PROV_VLANS))
                print("PERINGATAN: ONU PASS bisa drop sesaat.")
                confirm = input("Ketik SMARTPROV untuk lanjut: ").strip()
                if confirm != "SMARTPROV":
                    print("Batal.")
                    continue

                total_ok = total_all = 0
                try:
                    for r in range(1, MAX_PROV_ROUNDS + 1):
                        passed = get_pass_list(z, olt_if)
                        denied = get_deny_list(z, olt_if)
                        if not passed and not denied:
                            print(f"[Round {r}] Tidak ada ONU. STOP.")
                            break

                        plan = build_port_sequential_plan(passed, denied, available_types)
                        already_ok = all(it.old_id == it.new_id for it in plan)
                        if already_ok and r > 1:
                            print(f"[Round {r}] Sudah berurutan 1..N. STOP.")
                            break

                        print(f"\n[Round {r}] Total ONU (PASS+DENY)={len(plan)} | Target ID: 1..{len(plan)}")
                        ok, total = apply_plan_sequential_port(z, olt_if, onu_prefix, plan, PROV_VLANS)
                        total_ok += ok
                        total_all += total
                        time.sleep(SLEEP_BETWEEN_ROUNDS_SEC)

                except KeyboardInterrupt:
                    print("\n[STOP] dibatalkan (Ctrl+C).")
                except Exception as e:
                    print(f"\n[ERROR] {e}")

                print(f"\nSELESAI SMARTPROV. OK={total_ok}/{total_all}")
                continue

            if c == "9":
                with silent(log):
                    roots = discover_root_cards_from_help(z)
                    ports: List[str] = []
                    for r0 in roots:
                        ports.extend(expand_ports_from_root(r0, ports_per_card=8))

                    results: List[Tuple[str, int, int, int]] = []
                    grand_total = grand_pass = grand_deny = 0
                    for p in ports:
                        total, pcount, dcount = count_registered_on_port(z, p)
                        results.append((p, total, pcount, dcount))
                        grand_total += total
                        grand_pass += pcount
                        grand_deny += dcount

                print("\nCOUNT ONU TERDAFTAR (SEMUA CARD/PORT):")
                for p, total, pcount, dcount in results:
                    print(f" - {p}: TOTAL {total} | PASS {pcount} | DENY {dcount}")
                print(f"\nGRAND TOTAL: {grand_total} | PASS {grand_pass} | DENY {grand_deny}")
                continue

            if c == "13":
                if not available_types:
                    available_types = get_available_onu_types(z)
                available_types = mode_type_menu(z, olt_if, available_types)
                continue

            if c == "14":
                s = input("Masukkan ONU ID (cth 1-8 / 1,3,5): ").strip()
                ids = parse_csv_ints(s)
                if not ids:
                    print("Kosong.")
                    continue

                vlan_s = input("Masukkan VLAN (cth 16 / 16,52): ").strip()
                vlans = parse_csv_ints(vlan_s)
                if not vlans:
                    print("VLAN kosong.")
                    continue

                mode = input("Mode APPEND / REPLACE: ").strip().upper()
                if mode not in ("APPEND", "REPLACE"):
                    print("Mode tidak valid.")
                    continue

                confirm = input(f"Apply VLAN {vlans} mode={mode} ke ONU {ids}? ketik YES: ").strip()
                if confirm != "YES":
                    print("Batal.")
                    continue

                for onu_no in ids:
                    onu_if = f"{onu_prefix}{onu_no}"
                    print(f" - Apply VLAN {vlans} mode={mode} => {onu_if}")
                    set_onu_vlans(z, onu_if, vlans, mode=mode)
                    wr_after_each(z, note=f"VLAN {onu_if}")
                print("Selesai edit VLAN (WR per-ONU).")
                continue

            if c == "15":
                ids = get_all_onu_ids_on_port(z, olt_if)
                if not ids:
                    print("Tidak ada ONU terdeteksi (PASS/DENY) untuk dihapus.")
                    continue

                print(f"DELETE ALL akan hapus {len(ids)} ONU: {ids}")
                confirm = input("Ketik DELETEALL untuk lanjut: ").strip()
                if confirm != "DELETEALL":
                    print("Batal.")
                    continue

                delete_onu_ids(z, olt_if, ids)
                wr_after_each(z, note="DELETEALL")
                print("DELETE ALL selesai + WR.")
                continue

            if c == "16":
                clear_screen()
                print("\n=== LIST ONU CARD (TAHAP 1 CEPAT) ===")
                all_pass, all_prefix = print_card_quick(z, olt_if)
                choice = input("\nTekan ENTER untuk ambil TX/RX (atau ketik SKIP): ").strip().upper()
                if choice == "":
                    print_card_optic(z, all_pass, all_prefix)
                continue

            if c == "17":
                print("\n=== REBOOT ONU ===")
                print("1) Reboot ONU by ONU ID (di port aktif)")
                print("2) Reboot SEMUA ONU di port aktif")
                print("3) Reboot SEMUA ONU di CARD aktif (root card port aktif)")
                print("0) Kembali")
                ch = input("Pilih: ").strip()

                if ch == "0":
                    continue
                if ch == "1":
                    s = input("Masukkan ONU ID (cth 1-8 / 1,3,5): ").strip()
                    ids = parse_csv_ints(s)
                    reboot_by_ids_on_current_port(z, onu_prefix, ids)
                    continue
                if ch == "2":
                    reboot_all_on_current_port(z, olt_if, onu_prefix)
                    continue
                if ch == "3":
                    reboot_all_on_current_card(z, olt_if)
                    continue
                print("Pilihan tidak dikenal.")
                continue

            if c == "18":
                vlan_s = input("Masukkan VLAN custom (cth 16 / 16,52): ").strip()
                vlans = parse_csv_ints(vlan_s)
                if not vlans:
                    print("VLAN kosong.")
                    continue
                mode = input("Mode APPEND / REPLACE: ").strip().upper()
                if mode not in ("APPEND", "REPLACE"):
                    print("Mode tidak valid.")
                    continue
                update_vlan_all_pass_on_card(z, olt_if, vlans, mode)
                continue

            if c == "19":
                menu_uplink_vlan(z)
                continue

            if c == "20":
                menu_vlan_database(z)
                continue

            print("Pilihan tidak dikenal.")

    finally:
        z.close()
        log.info(f"LOG FILE: {log_file}")

if __name__ == "__main__":
    main()

