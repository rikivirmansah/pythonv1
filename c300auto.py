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

# Delay kecil untuk stabilkan echo/prompt
CMD_DELAY = 0.01

PROMPT_ANY_REGEX = re.compile(rb"ZXAN(?:\([^)]+\))?#\s*$", re.MULTILINE)
PROMPT_EXEC_REGEX = re.compile(rb"ZXAN#\s*$", re.MULTILINE)

LOGIN_USER = [b"Username:", b"username:", b"Login:", b"login:"]
LOGIN_PASS = [b"Password:", b"password:"]

DEFAULT_VLANS = [1002, 1001, 996, 33, 31, 30, 27, 25, 24, 1006, 562, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6]

# fallback TYPE optional (kosong = disable)
DEFAULT_ONU_TYPE = ""

# ===== Verifikasi cepat (tanpa delay fixed 3 detik) =====
VERIFY_MAX_WAIT_SEC = 0.8
VERIFY_POLL_INTERVAL_SEC = 0.2

# ===== WR: END + WR satu-satu setelah tiap sukses =====
WR_AFTER_EACH_SUCCESS = True
WR_DELAY_SEC = 0.2

# ===== SMART PROVISION =====
MAX_PROV_ROUNDS = 10
SLEEP_BETWEEN_ROUNDS_SEC = 0.5

# ===== Range ONU-ID =====
START_ONU_ID = 1
MAX_ONU_ID = 64

# ===== MODE 5: paksa penomoran ulang mulai dari 1 & unik =====
MODE5_RENUMBER_FROM_1 = True

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

    merged = []
    seen = set()
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

def olt_root_from_port(olt_port: str) -> Optional[str]:
    m = re.search(r"(epon-olt_\d+/\d+)(?:/\d+)?$", olt_port, re.IGNORECASE)
    return m.group(1).lower() if m else None

def onu_prefix_from_olt_port(olt_port: str) -> Optional[str]:
    m = re.search(r"epon-olt_(\d+/\d+/\d+)$", olt_port, re.IGNORECASE)
    if not m:
        return None
    return f"epon-onu_{m.group(1)}:"

# ===== MAC helper: FULL atau PREFIX (E0:38:3F:63) =====
def normalize_mac_or_prefix(s: str) -> Optional[str]:
    """
    Support input:
      - FULL MAC 12 hex -> 'xxxx.xxxx.xxxx'
      - PREFIX 8 hex (4 byte) -> 'xxxx.xxxx'
      - PREFIX 6 hex (3 byte/OUI) -> 'xxxx.xx'
    Accept separator: ., :, -, spasi
    """
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

    # ===== LOGIN CEPAT: tanpa loop cek berulang =====
    def login_fast(self, username: str, password: str):
        """
        Versi cepat: 1x kirim username/password, tunggu prompt.
        """
        self.log.info("LOGIN: fast")
        self.tn.write(b"\n")
        time.sleep(0.2)

        # tunggu salah satu prompt username atau sudah prompt CLI
        idx, _, _ = self.tn.expect(LOGIN_USER + [PROMPT_ANY_REGEX], 10)
        if idx == len(LOGIN_USER):  # sudah di CLI
            self.log.info("LOGIN OK (already logged in)")
            return

        # username
        self.tn.write(username.encode() + b"\n")
        self.tn.expect(LOGIN_PASS, 10)
        # password
        self.tn.write(password.encode() + b"\n")
        # tunggu prompt
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

# ================== SERVICE PORT READ/WRITE ==================
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

    # sesuai request: sebelum VLAN -> switch mode hybrid
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

# ================== TYPE PICKER ==================
def get_available_onu_types(z: ZXAN) -> List[str]:
    # dipanggil hanya saat diperlukan (biar startup cepat)
    with silent(z.log):
        enter_config(z)
        out = z.send_wait_any("show running-config", SHOW_TIMEOUT, "show-running-config")
        ensure_exec(z)
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

# ================== PROVISION CORE ==================
def get_denies_sorted(z: ZXAN, olt_if: str) -> List[OnuDeny]:
    out = show_unauthentication(z, olt_if, quiet=True)
    denies = parse_unauthentication_blocks(out)
    denies.sort(key=lambda x: x.onu_no)
    return denies

def get_denies_by_mac(z: ZXAN, olt_if: str) -> Dict[str, OnuDeny]:
    denies = get_denies_sorted(z, olt_if)
    mp: Dict[str, OnuDeny] = {}
    for d in denies:
        if d.mac:
            mp[d.mac.lower()] = d
    return mp

def get_pass_ids(z: ZXAN, olt_if: str) -> Set[int]:
    out = show_authentication(z, olt_if, quiet=True)
    passed = parse_authentication_blocks(out)
    return {p.onu_no for p in passed}

def is_mac_in_pass(z: ZXAN, olt_if: str, mac: str) -> bool:
    out = show_authentication(z, olt_if, quiet=True)
    passed = parse_authentication_blocks(out)
    m = mac.lower()
    return any((p.mgmt_mac or "").lower() == m for p in passed)

def fast_verify_mac_state(z: ZXAN, olt_if: str, mac: str) -> Tuple[bool, bool]:
    mac = mac.lower()
    t_end = time.time() + VERIFY_MAX_WAIT_SEC

    denies = get_denies_by_mac(z, olt_if)
    if mac not in denies:
        return True, is_mac_in_pass(z, olt_if, mac)

    while time.time() < t_end:
        time.sleep(VERIFY_POLL_INTERVAL_SEC)
        denies = get_denies_by_mac(z, olt_if)
        if mac not in denies:
            return True, is_mac_in_pass(z, olt_if, mac)

    return False, False

def rollback_onu_id(z: ZXAN, olt_if: str, onu_no: int, onu_prefix: str):
    try:
        enter_olt(z, olt_if)
        z.send_wait_any(f"no onu {onu_no}", 30, f"rollback-no-onu-{onu_no}")
        z.send_wait_any("exit", 20, "rollback-exit-olt")
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
    z.send_wait_any("exit", 20, "exit-olt")
    ensure_exec(z)
    return (not looks_like_error(out), out)

def apply_universal_onu_config(z: ZXAN, onu_if: str, vlans: List[int]):
    ensure_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg-onu-template")
    z.send_wait_any(f"interface {onu_if}", 20, f"enter-{onu_if}")

    # sesuai request: hilangkan ems-autocfg-request disable
    z.send_wait_any("switch mode hybrid", 20, f"hybrid-{onu_if}")
    z.send_wait_any("encrypt direction downstream  enable  vport 1", 20, f"enc-{onu_if}")

    for sp_id, vlan in enumerate(uniq_int_list(vlans), start=1):
        z.send_wait_any(f"service-port {sp_id} vport 1 user-vlan {vlan} vlan {vlan}", 30, f"sp-{onu_if}-{sp_id}")

    z.send_wait_any("exit", 20, f"exit-{onu_if}")
    ensure_exec(z)

def build_renumber_plan_from_1(denies: List[OnuDeny], pass_ids: Set[int]) -> Dict[str, Tuple[int, int]]:
    plan: Dict[str, Tuple[int, int]] = {}
    used: Set[int] = set(pass_ids)

    cur = START_ONU_ID
    for d in denies:
        if not d.mac:
            continue
        mac = d.mac.lower()
        old_id = int(d.onu_no)

        while cur in used:
            cur += 1
        if cur > MAX_ONU_ID:
            raise RuntimeError(f"ONU ID habis saat renumber. Range {START_ONU_ID}..{MAX_ONU_ID}")

        plan[mac] = (cur, old_id)
        used.add(cur)
        cur += 1
    return plan

def provision_mac_renumber_from_1(
    z: ZXAN, olt_if: str, onu_prefix: str, d: OnuDeny,
    available_types: List[str], new_id: int, old_id: int
) -> bool:
    mac = (d.mac or "").lower()
    model = d.model or "-"

    t = pick_type_from_model_strict(model, available_types)
    if not t and DEFAULT_ONU_TYPE:
        if any(x.lower() == DEFAULT_ONU_TYPE.lower() for x in available_types):
            t = next(x for x in available_types if x.lower() == DEFAULT_ONU_TYPE.lower())

    if not t:
        print(f" - MAC {mac} | MODEL {model}")
        print("   -> TYPE cocok tidak ditemukan. Buat onu-type via menu 13.")
        return False

    onu_if_new = f"{onu_prefix}{new_id}"
    print(f" - MAC {mac} | MODEL {model} | TYPE {t} | OLD_ID {old_id} -> NEW_ID {new_id}")

    rollback_onu_id(z, olt_if, old_id, onu_prefix)
    if new_id != old_id:
        rollback_onu_id(z, olt_if, new_id, onu_prefix)

    ok_add, add_out = try_add_onu_with_type(z, olt_if, new_id, t, mac)
    if not ok_add:
        print(f"   -> ADD GAGAL new_id={new_id} type={t}")
        print(extract_error_snippet(add_out))
        return False

    apply_universal_onu_config(z, onu_if_new, DEFAULT_VLANS)

    cleared, passed = fast_verify_mac_state(z, olt_if, mac)
    if cleared:
        print(f"   -> SUKSES: MAC keluar dari DENY" + (" & PASS terdeteksi" if passed else ""))
        wr_after_each(z, note=f"ONU {new_id}")
        return True

    print("   -> MASIH DENY: MAC masih muncul.")
    return False

# ================== SEARCH MAC (SEMUA PORT, FULL/PREFIX) ==================
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
                results.append({
                    "query": q, "mac": fm, "status": "DENY", "port": port,
                    "onu_id": str(d.onu_no), "model": d.model or "-", "type": "-", "last_auth": "-"
                })
                break

    out_pass = show_authentication(z, port, quiet=True)
    passed = parse_authentication_blocks(out_pass)
    for p in passed:
        fm = (p.mgmt_mac or "").lower()
        if not fm:
            continue
        for q in queries:
            if mac_match(fm, q):
                results.append({
                    "query": q, "mac": fm, "status": "PASS", "port": port,
                    "onu_id": str(p.onu_no), "model": "-", "type": p.onu_type or "-", "last_auth": p.last_auth_time or "-"
                })
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
            print(f"- MAC {r['mac']} | {r['status']} | PORT {r['port']} | ONU_ID {r['onu_id']} | TYPE {r['type']} | MODEL {r['model']} | LastAuth {r['last_auth']}")

# ================== BULK VLAN UPDATE (CARD AKTIF) ==================
def get_all_onu_ids_on_port(z: ZXAN, olt_if: str) -> List[int]:
    out_deny = show_unauthentication(z, olt_if, quiet=True)
    deny_ids = {d.onu_no for d in parse_unauthentication_blocks(out_deny)}
    out_pass = show_authentication(z, olt_if, quiet=True)
    pass_ids = {p.onu_no for p in parse_authentication_blocks(out_pass)}
    return sorted(deny_ids.union(pass_ids))

def update_vlan_all_onus_on_card(z: ZXAN, current_olt_if: str, vlans: List[int], mode: str):
    root = olt_root_from_port(current_olt_if)
    if not root:
        print("Gagal deteksi root card dari port aktif.")
        return

    ports = [f"{root}/{i}" for i in range(1, 9)]
    total_targets = 0

    # hitung dulu
    port_targets: List[Tuple[str, str, List[int]]] = []  # (port, onu_prefix, ids)
    for p in ports:
        pref = onu_prefix_from_olt_port(p) or ""
        ids = get_all_onu_ids_on_port(z, p)
        if ids:
            port_targets.append((p, pref, ids))
            total_targets += len(ids)

    if total_targets == 0:
        print("Tidak ada ONU terdeteksi pada card ini (semua port kosong).")
        return

    print("\n=== UPDATE VLAN SEMUA ONU DI CARD AKTIF ===")
    print(f"Root card: {root}")
    print(f"Mode: {mode} | VLAN: {uniq_int_list(vlans)}")
    for p, _, ids in port_targets:
        print(f" - {p}: {len(ids)} ONU")

    confirm = input("Ketik UPDATECARD untuk lanjut: ").strip()
    if confirm != "UPDATECARD":
        print("Batal.")
        return

    done = ok = 0
    for p, pref, ids in port_targets:
        print(f"\n[PORT {p}] update VLAN untuk {len(ids)} ONU ...")
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
    print(f"\nSelesai UPDATECARD VLAN. OK={ok}/{done}")

# ================== MODE 13 TYPE ==================
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
        print("3) Delete ONU PASS by TYPE (tidak ada di versi ini)")
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

# ================== MENU ==================
def menu():
    print("\n=== MENU ===")
    print("1) List ONU UNAUTH      [CLEAR SCREEN]")
    print("2) List ONU AUTH        [CLEAR SCREEN]")
    print("3) SEARCH ONU by MAC (SEMUA PORT) [FULL/PREFIX MAC]")
    print("5) SMART Provision (RENUNBER FROM 1, WR per ONU)")
    print("6) Ganti interface (port OLT)")
    print("9) Count ONU terdaftar di SEMUA card/port")
    print("13) MODE TYPE (fallback / show / tambah onu-type)")
    print("14) Edit VLAN ONU (APPEND/REPLACE) + WR SETIAP ONU")
    print("18) UPDATE VLAN SEMUA ONU DI CARD AKTIF (CUSTOM VLAN) + WR")
    print("0) Keluar")

# ================== MAIN ==================
def main():
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
        # LOGIN CEPAT (tanpa cek/loop yang bikin lama)
        z.login_fast(USERNAME, PASSWORD)

        # minim setup (cepat)
        ensure_exec(z)
        z.send_wait_any("terminal length 0", 10, "paging-length0")
        z.send_wait_any("terminal page 0", 10, "paging-page0")
        ensure_exec(z)

        # jangan auto-scan onu-type saat start (biar cepat)
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
                continue

            if c == "3":
                raw = input("Masukkan MAC / PREFIX (boleh banyak, pisah koma/spasi/enter):\n> ").strip()
                queries = parse_mac_inputs(raw)
                if not queries:
                    print("Input kosong / format salah. Contoh FULL: E0:38:3F:63:91:B7 | PREFIX: E0:38:3F:63")
                    continue
                print("Scan SEMUA port... (bisa agak lama)")
                results = search_macs_all_ports(z, queries)
                print_search_results(queries, results)
                continue

            if c == "5":
                # ambil type hanya saat mode 5 dipakai
                available_types = get_available_onu_types(z)

                print("\nSMART Provision:")
                print(" - Proses DENY di port aktif")
                print(" - Renumber mulai 1 & unik (skip ID yang dipakai PASS)")
                print(" - END+WR SETIAP ONU sukses\n")

                total_success = 0
                try:
                    for r in range(1, MAX_PROV_ROUNDS + 1):
                        denies = get_denies_sorted(z, olt_if)
                        if not denies:
                            print(f"[Round {r}] DENY kosong. STOP.")
                            break

                        pass_ids = get_pass_ids(z, olt_if)
                        plan = build_renumber_plan_from_1(denies, pass_ids)

                        print(f"\n[Round {r}] DENY devices={len(plan)} | Renumber mulai {START_ONU_ID}")
                        round_success = 0

                        for d in denies:
                            if not d.mac:
                                continue
                            mac = d.mac.lower()
                            if mac not in plan:
                                continue
                            if is_mac_in_pass(z, olt_if, mac):
                                print(f" - MAC {mac} sudah PASS (skip).")
                                continue

                            new_id, old_id = plan[mac]
                            if provision_mac_renumber_from_1(z, olt_if, onu_prefix, d, available_types, new_id, old_id):
                                round_success += 1
                                total_success += 1

                        deny_left = get_denies_by_mac(z, olt_if)
                        print(f"[Round {r}] Sisa DENY devices: {len(deny_left)}")

                        if round_success == 0:
                            print("[STOP] Tidak ada progress.")
                            break

                        time.sleep(SLEEP_BETWEEN_ROUNDS_SEC)

                except KeyboardInterrupt:
                    print("\n[STOP] Provision dibatalkan (Ctrl+C).")

                deny_final = get_denies_by_mac(z, olt_if)
                print(f"\nSELESAI. Total sukses={total_success}. SISA DENY={len(deny_final)}")
                continue

            if c == "9":
                with silent(log):
                    roots = discover_root_cards_from_help(z)
                    ports: List[str] = []
                    for r0 in roots:
                        ports.extend(expand_ports_from_root(r0, ports_per_card=8))

                    grand_total = grand_pass = grand_deny = 0
                    results: List[Tuple[str, int, int, int]] = []
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
                update_vlan_all_onus_on_card(z, olt_if, vlans, mode)
                continue

            print("Pilihan tidak dikenal.")

    finally:
        z.close()
        log.info(f"LOG FILE: {log_file}")

if __name__ == "__main__":
    main()
