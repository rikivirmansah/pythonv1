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
CMD_DELAY = 0.02

PROMPT_ANY_REGEX = re.compile(rb"ZXAN(?:\([^)]+\))?#\s*$", re.MULTILINE)
PROMPT_EXEC_REGEX = re.compile(rb"ZXAN#\s*$", re.MULTILINE)

LOGIN_USER = [b"Username:", b"username:", b"Login:", b"login:"]
LOGIN_PASS = [b"Password:", b"password:"]

DEFAULT_VLANS = [1002, 1001, 996, 33, 31, 30, 27, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6]

# fallback TYPE optional (kosong = disable)
DEFAULT_ONU_TYPE = ""

VERIFY_DELAY_SEC = 3.0

# ================== PERUBAHAN SESUAI REQUEST SEBELUMNYA ==================
WR_AFTER_EACH_SUCCESS = False     # dimatikan (WR per-ONU)
WR_DELAY_SEC = 1.0

MAX_PROV_ROUNDS = 10
SLEEP_BETWEEN_ROUNDS_SEC = 2.0

MAX_ONU_PER_ROUND = 20

START_ONU_ID = 1
MAX_ONU_ID = 64

OPTIC_CACHE_TTL_SEC = 30.0

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
    att_up_db: Optional[float] = None
    att_down_db: Optional[float] = None

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

def parse_pon_power_attenuation(text: str) -> OnuOptic:
    m_up = re.search(
        r"^\s*up\s+Rx\s*:\s*([+-]?\d+(?:\.\d+)?)\s*\(dbm\)\s+Tx\s*:\s*([+-]?\d+(?:\.\d+)?)\s*\(dbm\)\s+([+-]?\d+(?:\.\d+)?)\s*\(dB\)",
        text, re.IGNORECASE | re.MULTILINE
    )
    m_dn = re.search(
        r"^\s*down\s+Tx\s*:\s*([+-]?\d+(?:\.\d+)?)\s*\(dbm\)\s+Rx\s*:\s*([+-]?\d+(?:\.\d+)?)\s*\(dbm\)\s+([+-]?\d+(?:\.\d+)?)\s*\(dB\)",
        text, re.IGNORECASE | re.MULTILINE
    )
    up_tx = None
    dn_rx = None
    if m_up:
        up_tx = float(m_up.group(2))
    if m_dn:
        dn_rx = float(m_dn.group(2))
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
        time.sleep(CMD_DELAY)
        return self.read_until_any_prompt(timeout, label)

    def send_wait_exec(self, cmd: str, timeout: int, label: str) -> str:
        self.flush()
        self.log.info(f"SEND: {cmd}")
        self.tn.write(cmd.encode() + b"\n")
        time.sleep(CMD_DELAY)
        return self.read_until_exec(timeout, label)

    def login(self, username: str, password: str):
        self.log.info("LOGIN: start")
        self.tn.write(b"\n")
        time.sleep(0.2)
        self.tn.expect(LOGIN_USER + [PROMPT_ANY_REGEX], 20)

        for attempt in range(1, 4):
            self.log.info(f"LOGIN attempt {attempt}/3")
            self.tn.expect(LOGIN_USER, 20)
            self.tn.write(username.encode() + b"\n")
            self.tn.expect(LOGIN_PASS, 20)
            self.tn.write(password.encode() + b"\n")
            idx, _, data = self.tn.expect([PROMPT_ANY_REGEX] + LOGIN_USER, 30)
            out = data.decode(errors="ignore")
            if "No username or bad password" in out:
                continue
            if "ZXAN#" in out:
                self.log.info("LOGIN OK")
                return
        raise RuntimeError("Login gagal 3x")

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

def enter_config(z: ZXAN):
    go_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg")

def enter_olt(z: ZXAN, olt_if: str):
    go_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg")
    z.send_wait_any("interface epon", 20, "if-epon")
    z.send_wait_any("interface epon-olt", 20, "if-epon-olt")
    z.send_wait_any(f"interface {olt_if}", 20, "if-olt-target")

def end_wr(z: ZXAN):
    go_exec(z)
    z.send_wait_exec("wr", 180, "wr")

def wr_now(z: ZXAN, note: str = ""):
    if note:
        print(f"   -> WR NOW {note}")
    end_wr(z)
    time.sleep(WR_DELAY_SEC)

# ================== SHOW (quiet) ==================
def show_unauthentication(z: ZXAN, olt_if: str, quiet: bool = False) -> str:
    if quiet:
        with silent(z.log):
            enter_config(z)
            return z.send_wait_any(f"show onu unauthentication {olt_if}", SHOW_TIMEOUT, "show-unauthentication")
    enter_config(z)
    return z.send_wait_any(f"show onu unauthentication {olt_if}", SHOW_TIMEOUT, "show-unauthentication")

def show_authentication(z: ZXAN, olt_if: str, quiet: bool = False) -> str:
    if quiet:
        with silent(z.log):
            enter_config(z)
            return z.send_wait_any(f"show onu authentication {olt_if}", SHOW_TIMEOUT, "show-authentication")
    enter_config(z)
    return z.send_wait_any(f"show onu authentication {olt_if}", SHOW_TIMEOUT, "show-authentication")

def show_pon_power_attenuation(z: ZXAN, onu_if: str) -> str:
    with silent(z.log):
        go_exec(z)
        return z.send_wait_any(f"show pon power attenuation {onu_if}", 30, f"pon-power-atten-{onu_if}")

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

# ================== SERVICE PORT READ/WRITE ==================
def get_onu_service_ports(z: ZXAN, onu_if: str) -> Dict[int, int]:
    go_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg-onu-sp-read")
    z.send_wait_any(f"interface {onu_if}", 20, f"enter-{onu_if}")
    out = z.send_wait_any("show this", SHOW_TIMEOUT, f"show-this-{onu_if}")
    z.send_wait_any("exit", 20, f"exit-{onu_if}")
    return parse_service_ports(out)

def set_onu_vlans(z: ZXAN, onu_if: str, vlans: List[int], mode: str = "APPEND"):
    mode = mode.upper().strip()
    target_vlans = uniq_int_list(vlans)
    if not target_vlans:
        return

    existing = get_onu_service_ports(z, onu_if)
    existing_vlans = set(existing.values())

    go_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg-onu-sp-write")
    z.send_wait_any(f"interface {onu_if}", 20, f"enter-{onu_if}")

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

# ================== TYPE PICKER ==================
def get_available_onu_types(z: ZXAN) -> List[str]:
    with silent(z.log):
        enter_config(z)
        out = z.send_wait_any("show running-config", SHOW_TIMEOUT, "show-running-config")
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

# ================== ONU ID MAPPING (V2) ==================
MAC_TO_ONU_ID: Dict[str, int] = {}
NEXT_ONU_ID = START_ONU_ID

def get_used_onu_ids(z: ZXAN, olt_if: str) -> Set[int]:
    used: Set[int] = set()
    out_deny = show_unauthentication(z, olt_if, quiet=True)
    denies = parse_unauthentication_blocks(out_deny)
    used |= {d.onu_no for d in denies}

    out_pass = show_authentication(z, olt_if, quiet=True)
    passed = parse_authentication_blocks(out_pass)
    used |= {p.onu_no for p in passed}

    used |= set(MAC_TO_ONU_ID.values())
    return used

def assign_onu_id_for_mac(z: ZXAN, olt_if: str, mac: str) -> int:
    global NEXT_ONU_ID
    mac = mac.lower()
    if mac in MAC_TO_ONU_ID:
        return MAC_TO_ONU_ID[mac]

    used = get_used_onu_ids(z, olt_if)
    candidate = max(NEXT_ONU_ID, START_ONU_ID)

    while candidate in used:
        candidate += 1
        if candidate > MAX_ONU_ID:
            raise RuntimeError(f"ONU ID habis. Cek range {START_ONU_ID}..{MAX_ONU_ID}")

    MAC_TO_ONU_ID[mac] = candidate
    NEXT_ONU_ID = candidate + 1
    return candidate

# ================== PROVISION CORE (MAC-driven + fixed ONU-ID) ==================
def get_denies_by_mac(z: ZXAN, olt_if: str) -> Dict[str, OnuDeny]:
    out = show_unauthentication(z, olt_if, quiet=True)
    denies = parse_unauthentication_blocks(out)
    mp: Dict[str, OnuDeny] = {}
    for d in denies:
        if d.mac:
            mp[d.mac.lower()] = d
    return mp

def is_mac_in_pass(z: ZXAN, olt_if: str, mac: str) -> bool:
    out = show_authentication(z, olt_if, quiet=True)
    passed = parse_authentication_blocks(out)
    m = mac.lower()
    return any((p.mgmt_mac or "").lower() == m for p in passed)

def rollback_onu_id(z: ZXAN, olt_if: str, onu_no: int, onu_prefix: str):
    try:
        enter_olt(z, olt_if)
        z.send_wait_any(f"no onu {onu_no}", 30, f"rollback-no-onu-{onu_no}")
        z.send_wait_any("exit", 20, "rollback-exit-olt")
    except Exception:
        pass

    onu_if = f"{onu_prefix}{onu_no}"
    try:
        go_exec(z)
        z.send_wait_any("configure terminal", 20, "rollback-cfg-onu")
        z.send_wait_any(f"interface {onu_if}", 20, f"rollback-enter-{onu_if}")
        z.send_wait_any("deregister", 20, f"rollback-deregister-{onu_if}")
        z.send_wait_any("deactivate", 20, f"rollback-deactivate-{onu_if}")
        z.send_wait_any("exit", 20, f"rollback-exit-{onu_if}")
    except Exception:
        pass

def try_add_onu_with_type(z: ZXAN, olt_if: str, onu_no: int, onu_type: str, mac: str) -> Tuple[bool, str]:
    enter_olt(z, olt_if)
    out = z.send_wait_any(f"onu {onu_no} type {onu_type} mac {mac} ip-cfg static", 60, f"add-onu-{onu_no}-{onu_type}")
    z.send_wait_any("exit", 20, "exit-olt")
    return (not looks_like_error(out), out)

def apply_universal_onu_config(z: ZXAN, onu_if: str, vlans: List[int]):
    go_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg-onu-template")
    z.send_wait_any(f"interface {onu_if}", 20, f"enter-{onu_if}")

    for cmd in [
        "ems-autocfg-request disable",
        "encrypt direction downstream  enable  vport 1",
    ]:
        out = z.send_wait_any(cmd, 20, f"tmpl-{onu_if}")
        if looks_like_error(out):
            print(f"   -> WARN CONFIG gagal: '{cmd}'")
            print(extract_error_snippet(out))

    for sp_id, vlan in enumerate(uniq_int_list(vlans), start=1):
        out = z.send_wait_any(f"service-port {sp_id} vport 1 user-vlan {vlan} vlan {vlan}", 30, f"sp-{onu_if}-{sp_id}")
        if looks_like_error(out):
            print(f"   -> WARN SERVICE-PORT gagal: vlan={vlan} (sp_id={sp_id})")
            print(extract_error_snippet(out))

    z.send_wait_any("exit", 20, f"exit-{onu_if}")

def provision_mac_v2(z: ZXAN, olt_if: str, onu_prefix: str, mac: str, model_hint: Optional[str], available_types: List[str]) -> bool:
    mac = mac.lower()

    denies_map = get_denies_by_mac(z, olt_if)
    if mac not in denies_map:
        if is_mac_in_pass(z, olt_if, mac):
            print(f" - MAC {mac} sudah PASS (skip).")
            return True
        print(f" - MAC {mac} tidak ada di DENY saat ini (skip).")
        return True

    model = denies_map[mac].model or model_hint or "-"

    t = pick_type_from_model_strict(model, available_types)
    if not t and DEFAULT_ONU_TYPE:
        if any(x.lower() == DEFAULT_ONU_TYPE.lower() for x in available_types):
            t = next(x for x in available_types if x.lower() == DEFAULT_ONU_TYPE.lower())

    if not t:
        print(f" - MAC {mac} | MODEL {model}")
        print("   -> TYPE cocok tidak ditemukan. Buat onu-type via menu 13.")
        return False

    onu_id = assign_onu_id_for_mac(z, olt_if, mac)
    onu_if = f"{onu_prefix}{onu_id}"

    print(f" - MAC {mac} | MODEL {model} | TYPE {t} | ONU_ID {onu_id}")

    rollback_onu_id(z, olt_if, onu_id, onu_prefix)

    ok_add, add_out = try_add_onu_with_type(z, olt_if, onu_id, t, mac)
    if not ok_add:
        print(f"   -> ADD GAGAL type={t} onu_id={onu_id}")
        print(extract_error_snippet(add_out))
        return False

    apply_universal_onu_config(z, onu_if, DEFAULT_VLANS)
    time.sleep(VERIFY_DELAY_SEC)

    denies_map2 = get_denies_by_mac(z, olt_if)
    if mac not in denies_map2:
        passed = is_mac_in_pass(z, olt_if, mac)
        print(f"   -> SUKSES: MAC keluar dari DENY" + (" & PASS terdeteksi" if passed else ""))
        return True

    print(f"   -> MASIH DENY: MAC masih muncul.")
    return False

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
    z.send_wait_any("exit", 20, "exit-olt-delete")

# ================== MENU 17: REBOOT ONU ==================
def reboot_onu(z: ZXAN, onu_if: str) -> bool:
    """
    Sesuai contoh:
      config t
      pon-onu
      pon-onu-mng epon-onu_1/2/5:5
      reboot
    """
    onu_if = onu_if.strip()
    if not onu_if:
        return False

    go_exec(z)
    z.send_wait_any("configure terminal", 20, "reboot-cfg")
    z.send_wait_any("pon-onu", 20, "reboot-pon-onu")
    z.send_wait_any(f"pon-onu-mng {onu_if}", 20, f"reboot-mng-{onu_if}")
    out = z.send_wait_any("reboot", 60, f"reboot-{onu_if}")

    # keluar dari mode mng -> pon-onu -> config
    z.send_wait_any("exit", 20, f"reboot-exit-mng-{onu_if}")
    z.send_wait_any("exit", 20, f"reboot-exit-pon-onu-{onu_if}")

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
    # hitung total dulu biar jelas
    port_map: Dict[str, Tuple[str, List[int]]] = {}  # port -> (onu_prefix, ids)
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
    for p, (pref, ids) in port_map.items():
        print(f" - {p}: total={len(ids)} | IDs={ids}")

    confirm = input(f"Ketik REBOOTCARD untuk lanjut reboot total {total} ONU: ").strip()
    if confirm != "REBOOTCARD":
        print("Batal.")
        return

    ok = 0
    done = 0
    for p, (pref, ids) in port_map.items():
        print(f"\n[PORT {p}] reboot {len(ids)} ONU ...")
        for onu_no in ids:
            onu_if = f"{pref}{onu_no}"
            if reboot_onu(z, onu_if):
                ok += 1
            done += 1
            time.sleep(0.2)
    print(f"\nSelesai reboot card. OK={ok}/{done}")

# ================== MENU 16: 2 TAHAP ==================
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

        onu_prefix = onu_prefix_from_olt_port(port) or ""
        all_prefix[port] = onu_prefix
        all_pass[port] = passed

        print(f"\n--- PORT {port} | PASS {len(passed)} | DENY {len(denies)} ---")

        if passed:
            print("PASS (tanpa TX/RX):")
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
        onu_prefix = all_prefix.get(port, "")
        print(f"\n--- PORT {port} | PASS {len(passed)} (TX/RX) ---")
        for p in passed:
            onu_if = f"{onu_prefix}{p.onu_no}"
            optic = get_onu_optic_cached(z, onu_if)
            tx = f"{optic.onu_tx_up_dbm:.3f} dBm" if optic.onu_tx_up_dbm is not None else "-"
            rx = f"{optic.onu_rx_down_dbm:.3f} dBm" if optic.onu_rx_down_dbm is not None else "-"
            print(f" - ONU {p.onu_no} | TYPE {p.onu_type or '-'} | TX {tx} | RX {rx}")

# ================== MENU 9 COUNT ALL PORTS ==================
def discover_root_cards_from_help(z: ZXAN) -> List[str]:
    go_exec(z)
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
            end_wr(z)
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
            print("\nAkan buat ONU TYPE dengan setting:")
            print(f" - TYPE: {onu_type}")
            print(f" - ETH: {eth_ports} | WIFI SSIDs: {wifi_ssids} | VoIP: {voip_ports}")
            confirm = input("Ketik YES untuk lanjut: ").strip()
            if confirm != "YES":
                print("Batal.")
                continue
            add_onu_type_epon(z, onu_type, eth_ports, wifi_ssids, voip_ports)
            end_wr(z)
            print("Tambah ONU TYPE selesai + WR.")
            print("Refresh daftar TYPE...")
            available_types = get_available_onu_types(z)
            continue

        print("Pilihan tidak dikenal.")

# ================== MENU ==================
def menu():
    print("\n=== MENU ===")
    print("1) List ONU UNAUTH (deny) + MAC/MODEL      [CLEAR SCREEN]")
    print("2) AUTH PASS (2 tahap: cepat -> ENTER TX/RX) [CLEAR SCREEN]")
    print("5) SMART Provision DENY (V2 MAC+FIXED ONU-ID, max 20/round) + WR DI AKHIR SAJA")
    print("6) Ganti interface (port OLT)")
    print("9) Count ONU terdaftar di SEMUA card/port")
    print("13) MODE TYPE (fallback / show / delete / tambah onu-type)")
    print("14) Edit VLAN ONU (APPEND/REPLACE) + WR")
    print("15) DELETE ALL ONU di port ini + WR")
    print("16) PRINT ONU di CARD aktif (2 tahap: cepat -> ENTER TX/RX)")
    print("17) REBOOT ONU (by ID / all port / all card)")
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
        z.login(USERNAME, PASSWORD)

        go_exec(z)
        z.send_wait_any("terminal length 0", 10, "paging-length0")
        z.send_wait_any("terminal page 0", 10, "paging-page0")

        available_types = get_available_onu_types(z)
        print(f"\nTotal TYPE ditemukan: {len(available_types)}")

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

            if c == "5":
                available_types = get_available_onu_types(z)

                print("\nSMART Provision V2: MAC full + ONU-ID fixed. Max 20 ONU/round.")
                print(f"ONU-ID range: {START_ONU_ID}..{MAX_ONU_ID} | Start={START_ONU_ID}")
                print("Eksekusi langsung (tanpa konfirmasi). WR hanya di akhir jika ada sukses.\n")

                total_success = 0
                try:
                    for r in range(1, MAX_PROV_ROUNDS + 1):
                        denies_map = get_denies_by_mac(z, olt_if)
                        if not denies_map:
                            print(f"[Round {r}] DENY kosong. STOP.")
                            break

                        mac_list = sorted(denies_map.keys())
                        if len(mac_list) > MAX_ONU_PER_ROUND:
                            print(f"[Round {r}] DENY devices={len(mac_list)}. Diproses hanya {MAX_ONU_PER_ROUND}, sisanya ditahan.")
                            mac_list = mac_list[:MAX_ONU_PER_ROUND]

                        print(f"\n[Round {r}] Proses {len(mac_list)} DENY device(s) ...")

                        round_success = 0
                        for mac in mac_list:
                            model_hint = denies_map[mac].model if mac in denies_map else None
                            if provision_mac_v2(z, olt_if, onu_prefix, mac, model_hint, available_types):
                                round_success += 1
                                total_success += 1

                        deny_left = get_denies_by_mac(z, olt_if)
                        print(f"[Round {r}] Sisa DENY devices: {len(deny_left)}")

                        if round_success == 0:
                            print("[STOP] Tidak ada progress. Biasanya type belum tersedia atau auth port tidak cocok.")
                            break

                        time.sleep(SLEEP_BETWEEN_ROUNDS_SEC)

                except KeyboardInterrupt:
                    print("\n[STOP] Provision dibatalkan (Ctrl+C).")

                deny_final = get_denies_by_mac(z, olt_if)
                print(f"\nSELESAI. Total sukses (attempt)={total_success}. SISA DENY devices={len(deny_final)}")
                for mac, d in deny_final.items():
                    print(f" - ONU? {d.onu_no} | MAC {mac} | MODEL {d.model or '-'}")

                if total_success > 0:
                    print("\nMenjalankan END + WR sekali di akhir (ada perubahan)...")
                    end_wr(z)
                    print("END + WR selesai.")
                else:
                    print("\nTidak ada sukses, tidak menjalankan WR.")
                continue

            if c == "9":
                with silent(log):
                    roots = discover_root_cards_from_help(z)
                    ports: List[str] = []
                    for r in roots:
                        ports.extend(expand_ports_from_root(r, ports_per_card=8))

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

                end_wr(z)
                print("Selesai edit VLAN + WR.")
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
                end_wr(z)
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

            print("Pilihan tidak dikenal.")

    finally:
        z.close()
        log.info(f"LOG FILE: {log_file}")

if __name__ == "__main__":
    main()
