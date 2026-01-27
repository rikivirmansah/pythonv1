#!/usr/bin/env python3
import os
import re
import telnetlib
import time
import random
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

# ================== KONFIG ==================
HOST = "136.1.1.100"
PORT = 23
USERNAME = "zte"
PASSWORD = "zte"

TIMEOUT = 30
SHOW_TIMEOUT = 180
CMD_DELAY = 0.02

PROMPT_EXEC = b"ZXAN#"
PROMPT_CFG = b"ZXAN(config)#"
PROMPT_CFGIF = b"ZXAN(config-if)#"

# Prompt fleksibel: ZXAN(config)# / ZXAN(config-xxx)# / ZXAN# dll
PROMPT_ANY_REGEX = re.compile(rb"ZXAN(?:\([^)]+\))?#\s*$", re.MULTILINE)

LOGIN_USER = [b"Username:", b"username:", b"Login:", b"login:"]
LOGIN_PASS = [b"Password:", b"password:"]

DEFAULT_VLANS = [16]
DEFAULT_ONU_TYPE = "ALL-EPON"

MAX_TYPE_TRIES_PER_MAC = 20
VERIFY_DELAY_SEC = 3.0
MAX_GLOBAL_ROUNDS = 20

# ================== UTIL ==================
def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def looks_like_error(out: str) -> bool:
    t = out.lower()
    err_keys = [
        "%error", "invalid", "fail", "failed", "unknown", "incomplete",
        "ambiguous", "denied", "not supported", "error"
    ]
    return any(k in t for k in err_keys)

def norm_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return mac.strip().lower()

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
    return uniq_int_list(out)

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

    def dump(self, title: str, data: str):
        self.info(f"{title} (len={len(data)})")
        with open(self.filename, "a", encoding="utf-8") as f:
            f.write("----- BEGIN DUMP -----\n")
            f.write(data + "\n")
            f.write("----- END DUMP -------\n")

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
    mgmt_sn: Optional[str]
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

        m_mgmt_sn = re.search(r"^\s*Mgmt SN\s*:\s*(\S+)\s*$", b, re.IGNORECASE | re.MULTILINE)
        mgmt_sn = m_mgmt_sn.group(1) if m_mgmt_sn else None

        m_last = re.search(r"LastAuthTime\s*:\s*(.+)", b, re.IGNORECASE)
        last_auth = m_last.group(1).strip() if m_last else None

        items.append(OnuPass(
            onu_no=onu_no,
            onu_type=onu_type,
            mgmt_mac=mgmt_mac,
            mgmt_sn=mgmt_sn,
            last_auth_time=last_auth
        ))

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

def parse_range_ids(s: str) -> List[int]:
    return parse_csv_ints(s)

# ================== TELNET CORE ==================
class ZXAN:
    def __init__(self, host: str, port: int, log: Logger):
        self.log = log
        self.tn = telnetlib.Telnet(host, port, TIMEOUT)
        self.log.info(f"Connected TCP {host}:{port}")

    def flush(self):
        junk = self.tn.read_very_eager()
        if junk:
            self.log.dump("FLUSH", junk.decode(errors="ignore"))

    def read_until_any_prompt(self, timeout: int, label: str) -> str:
        self.log.info(f"WAIT ({label}) until ANY ZXAN prompt timeout={timeout}s")
        idx, _, data = self.tn.expect([PROMPT_ANY_REGEX], timeout)
        out = data.decode(errors="ignore")
        if idx < 0:
            self.log.dump(f"TIMEOUT ({label})", out)
            raise TimeoutError(f"Timeout waiting ANY prompt ({label}). Cek log {self.log.filename}")
        return out

    def send_wait_any(self, cmd: str, timeout: int, label: str) -> str:
        self.flush()
        self.log.info(f"SEND: {cmd}")
        self.tn.write(cmd.encode() + b"\n")
        time.sleep(CMD_DELAY)
        return self.read_until_any_prompt(timeout, label)

    def login(self, username: str, password: str):
        self.log.info("LOGIN: start")
        self.tn.write(b"\n")
        time.sleep(0.2)
        self.tn.expect(LOGIN_USER + [PROMPT_EXEC, PROMPT_CFG, PROMPT_CFGIF, PROMPT_ANY_REGEX], 20)

        for attempt in range(1, 4):
            self.log.info(f"LOGIN attempt {attempt}/3")
            self.tn.expect(LOGIN_USER, 20)
            self.tn.write(username.encode() + b"\n")
            self.tn.expect(LOGIN_PASS, 20)
            self.tn.write(password.encode() + b"\n")
            idx, _, data = self.tn.expect([PROMPT_ANY_REGEX] + LOGIN_USER, 30)
            out = data.decode(errors="ignore")
            if "No username or bad password" in out:
                self.log.dump("LOGIN FAILED", out)
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
    z.send_wait_any("end", 20, "go-exec")

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
    z.send_wait_any("wr", 180, "wr")

# ================== SHOW COMMANDS ==================
def show_unauthentication(z: ZXAN, olt_if: str) -> str:
    enter_config(z)
    return z.send_wait_any(f"show onu unauthentication {olt_if}", SHOW_TIMEOUT, "show-unauthentication")

def show_authentication(z: ZXAN, olt_if: str) -> str:
    enter_config(z)
    return z.send_wait_any(f"show onu authentication {olt_if}", SHOW_TIMEOUT, "show-authentication")

def get_onu_service_ports(z: ZXAN, onu_if: str) -> Dict[int, int]:
    go_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg-onu-sp-read")
    z.send_wait_any(f"interface {onu_if}", 20, f"enter-{onu_if}")

    out = z.send_wait_any("show this", SHOW_TIMEOUT, f"show-this-{onu_if}")
    if ("Invalid" in out) or ("%Error" in out):
        out = z.send_wait_any("show", SHOW_TIMEOUT, f"show-{onu_if}")

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
            z.send_wait_any(
                f"service-port {sp_id} vport 1 user-vlan {vlan} vlan {vlan}",
                30, f"sp-{onu_if}-{sp_id}"
            )
    else:
        to_add = [v for v in target_vlans if v not in existing_vlans]
        if to_add:
            next_id = (max(existing.keys()) + 1) if existing else 1
            for vlan in to_add:
                z.send_wait_any(
                    f"service-port {next_id} vport 1 user-vlan {vlan} vlan {vlan}",
                    30, f"sp-{onu_if}-{next_id}"
                )
                next_id += 1

    z.send_wait_any("exit", 20, f"exit-{onu_if}")

# ================== DELETE ALL ONU (PORT) ==================
def get_all_onu_ids_on_port(z: ZXAN, olt_if: str) -> List[int]:
    out_deny = show_unauthentication(z, olt_if)
    deny_ids = {d.onu_no for d in parse_unauthentication_blocks(out_deny)}
    out_pass = show_authentication(z, olt_if)
    pass_ids = {p.onu_no for p in parse_authentication_blocks(out_pass)}
    return sorted(deny_ids.union(pass_ids))

def delete_onu_ids(z: ZXAN, olt_if: str, ids: List[int]):
    if not ids:
        return
    enter_olt(z, olt_if)
    for onu_no in ids:
        z.send_wait_any(f"no onu {onu_no}", 30, f"no-onu-{onu_no}")
    z.send_wait_any("exit", 20, "exit-olt-delete")

# ================== MENU 9 COUNT ALL PORTS ==================
def discover_root_cards_from_help(z: ZXAN) -> List[str]:
    go_exec(z)
    out = z.send_wait_any("show interface ?", SHOW_TIMEOUT, "discover-root-help")
    roots = sorted(set(re.findall(r"\b(epon-olt_\d+/\d+)\b", out, flags=re.IGNORECASE)))
    return [r.lower() for r in roots]

def expand_ports_from_root(root: str, ports_per_card: int = 8) -> List[str]:
    return [f"{root}/{i}" for i in range(1, ports_per_card + 1)]

def count_registered_on_port(z: ZXAN, port: str) -> Tuple[int, int, int]:
    out_deny = show_unauthentication(z, port)
    deny_ids = {d.onu_no for d in parse_unauthentication_blocks(out_deny)}
    out_pass = show_authentication(z, port)
    pass_ids = {p.onu_no for p in parse_authentication_blocks(out_pass)}
    total_ids = deny_ids.union(pass_ids)
    return (len(total_ids), len(pass_ids), len(deny_ids))

# ================== TYPE DISCOVERY + PICKER ==================
def get_available_onu_types(z: ZXAN) -> List[str]:
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
    return m

def pick_type_from_model(model: Optional[str], available_types: List[str]) -> Optional[str]:
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

def build_type_candidates(model: Optional[str], available_types: List[str]) -> List[str]:
    candidates: List[str] = []
    used: Set[str] = set()

    best = pick_type_from_model(model, available_types)
    if best:
        candidates.append(best)
        used.add(best.lower())

    if DEFAULT_ONU_TYPE and any(t.lower() == DEFAULT_ONU_TYPE.lower() for t in available_types):
        if DEFAULT_ONU_TYPE.lower() not in used:
            real = next(t for t in available_types if t.lower() == DEFAULT_ONU_TYPE.lower())
            candidates.append(real)
            used.add(real.lower())

    rest = [t for t in available_types if t.lower() not in used]
    random.shuffle(rest)
    candidates.extend(rest)
    return candidates

# ================== UNIVERSAL ONU CONFIG ==================
def apply_universal_onu_config(z: ZXAN, onu_if: str, vlans: List[int]):
    go_exec(z)
    z.send_wait_any("configure terminal", 20, "cfg-onu-template")
    z.send_wait_any(f"interface {onu_if}", 20, f"enter-{onu_if}")

    # tolerant
    for cmd, label in [
        ("ems-autocfg-request disable", "ems-autocfg"),
        ("encrypt direction downstream  enable  vport 1", "encrypt-ds"),
    ]:
        out = z.send_wait_any(cmd, 20, f"{label}-{onu_if}")
        if looks_like_error(out):
            pass

    for sp_id, vlan in enumerate(uniq_int_list(vlans), start=1):
        out = z.send_wait_any(
            f"service-port {sp_id} vport 1 user-vlan {vlan} vlan {vlan}",
            30, f"sp-{onu_if}-{sp_id}"
        )
        if looks_like_error(out):
            pass

    z.send_wait_any("exit", 20, f"exit-{onu_if}")

# ================== PROVISION MEMORY ==================
class ProvisionMemory:
    def __init__(self):
        self.success_type: Dict[str, str] = {}
        self.tried: Dict[str, Set[str]] = {}

    def get_success(self, mac: str) -> Optional[str]:
        return self.success_type.get(mac)

    def mark_success(self, mac: str, onu_type: str):
        self.success_type[mac] = onu_type

    def mark_tried(self, mac: str, onu_type: str):
        self.tried.setdefault(mac, set()).add(onu_type.lower())

    def has_tried(self, mac: str, onu_type: str) -> bool:
        return onu_type.lower() in self.tried.get(mac, set())

class VlanMemory:
    def __init__(self):
        self.mac_vlans: Dict[str, List[int]] = {}

    def set(self, mac: str, vlans: List[int]):
        self.mac_vlans[mac.lower()] = uniq_int_list(vlans)

    def get(self, mac: str) -> Optional[List[int]]:
        return self.mac_vlans.get(mac.lower())

PROV_MEM = ProvisionMemory()
VLAN_MEM = VlanMemory()

# ================== PROVISION CORE ==================
def get_current_deny_macs(z: ZXAN, olt_if: str) -> Set[str]:
    out = show_unauthentication(z, olt_if)
    denies = parse_unauthentication_blocks(out)
    macs = set()
    for d in denies:
        m = norm_mac(d.mac)
        if m:
            macs.add(m)
    return macs

def try_add_onu_with_type(z: ZXAN, olt_if: str, onu_no: int, onu_type: str, mac: str) -> Tuple[bool, str]:
    enter_olt(z, olt_if)
    out = z.send_wait_any(
        f"onu {onu_no} type {onu_type} mac {mac} ip-cfg auto-cfg",
        60, f"add-onu-{onu_no}-{onu_type}"
    )
    z.send_wait_any("exit", 20, "exit-olt")
    return (not looks_like_error(out), out)

def rollback_onu(z: ZXAN, olt_if: str, onu_no: int, onu_prefix: str):
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

def provision_one_deny_until_gone(
    z: ZXAN,
    olt_if: str,
    onu_prefix: str,
    deny: OnuDeny,
    available_types: List[str]
) -> bool:
    mac = norm_mac(deny.mac)
    if not mac:
        print(f" - ONU {deny.onu_no} skip: MAC kosong")
        return False

    preferred = PROV_MEM.get_success(mac)
    candidates = build_type_candidates(deny.model, available_types)

    try_list: List[str] = []
    if preferred and any(t.lower() == preferred.lower() for t in available_types):
        real_pref = next(t for t in available_types if t.lower() == preferred.lower())
        try_list.append(real_pref)

    for t in candidates:
        if len(try_list) >= MAX_TYPE_TRIES_PER_MAC:
            break
        if t.lower() == (preferred or "").lower():
            continue
        if PROV_MEM.has_tried(mac, t):
            continue
        try_list.append(t)

    if not try_list:
        rest = [t for t in available_types if not PROV_MEM.has_tried(mac, t)]
        random.shuffle(rest)
        try_list = rest[:MAX_TYPE_TRIES_PER_MAC]
        if not try_list and available_types:
            try_list = available_types[:MAX_TYPE_TRIES_PER_MAC]

    print(f" - ONU {deny.onu_no} | MAC {mac} | MODEL {deny.model or '-'} | Try={len(try_list)}")

    for idx, onu_type in enumerate(try_list, start=1):
        PROV_MEM.mark_tried(mac, onu_type)

        ok_add, _ = try_add_onu_with_type(z, olt_if, deny.onu_no, onu_type, mac)
        if not ok_add:
            print(f"   -> ADD GAGAL type={onu_type} (try {idx}/{len(try_list)})")
            continue

        onu_if = f"{onu_prefix}{deny.onu_no}"
        vlans_to_apply = VLAN_MEM.get(mac) or DEFAULT_VLANS
        apply_universal_onu_config(z, onu_if, vlans_to_apply)

        time.sleep(VERIFY_DELAY_SEC)
        deny_macs_now = get_current_deny_macs(z, olt_if)
        if mac not in deny_macs_now:
            print(f"   -> SUKSES type={onu_type} (MAC hilang dari UNAUTH) VLAN={vlans_to_apply}")
            PROV_MEM.mark_success(mac, onu_type)
            return True

        print(f"   -> MASIH UNAUTH (type={onu_type}) => rollback & coba type lain")
        rollback_onu(z, olt_if, deny.onu_no, onu_prefix)

    print(f"   -> GAGAL TOTAL: MAC {mac} masih UNAUTH setelah semua type dicoba.")
    return False

# ================== FORCE FIX DENY ==================
def force_fix_deny_on_port(z: ZXAN, olt_if: str, onu_prefix: str):
    out = show_unauthentication(z, olt_if)
    denies = parse_unauthentication_blocks(out)
    if not denies:
        print("Tidak ada ONU DENY pada port ini.")
        return

    print(f"\nDENY ditemukan: {len(denies)} ONU")
    for d in denies:
        print(f" - ONU {d.onu_no} | MAC {d.mac or '-'} | MODEL {d.model or '-'}")

    confirm = input("Ketik FIX untuk lanjut rollback (no onu + dereg/deact): ").strip()
    if confirm != "FIX":
        print("Batal.")
        return

    for d in denies:
        rollback_onu(z, olt_if, d.onu_no, onu_prefix)

    end_wr(z)
    print("Force-fix selesai + WR.")

# ================== SMART AUTO LOOP ==================
def smart_auto_provision_until_clear(z: ZXAN, olt_if: str, onu_prefix: str, available_types: List[str], max_round: int):
    processed_ok = 0

    for r in range(1, max_round + 1):
        out = show_unauthentication(z, olt_if)
        denies = parse_unauthentication_blocks(out)
        if not denies:
            print(f"[Round {r}] DENY kosong -> STOP.")
            break

        print(f"\n[Round {r}] DENY count={len(denies)} -> provision sampai MAC hilang dari UNAUTH...")
        progress = 0

        for d in denies:
            if provision_one_deny_until_gone(z, olt_if, onu_prefix, d, available_types):
                processed_ok += 1
                progress += 1

        out2 = show_unauthentication(z, olt_if)
        denies2 = parse_unauthentication_blocks(out2)
        if not denies2:
            print(f"[Round {r}] DENY sekarang kosong -> selesai.")
            break

        if progress == 0:
            print(f"[Round {r}] Tidak ada progress -> STOP.")
            break

        time.sleep(1.0)

    end_wr(z)
    print(f"\nSMART AUTO-PROVISION selesai. Total sukses: {processed_ok}. WR sudah dijalankan.")

# ================== ONU TYPE ADDER ==================
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

# ================== MODE 13 TYPE ==================
def mode_type_menu(z: ZXAN, olt_if: str, available_types: List[str]) -> List[str]:
    global DEFAULT_ONU_TYPE

    while True:
        print("\n=== MODE 13: TYPE ===")
        print(f"DEFAULT TYPE (fallback) = {DEFAULT_ONU_TYPE}")
        print("1) Set DEFAULT TYPE (fallback)")
        print("2) Show TYPE ONU PASS (di port aktif)")
        print("3) Delete ONU PASS by TYPE (no onu) + WR")
        print("4) Tambah ONU TYPE (register type + port map) + WR")
        print("0) Kembali")
        ch = input("Pilih: ").strip()

        if ch == "0":
            return available_types

        if ch == "1":
            t = input("Masukkan TYPE fallback baru (contoh ALL-EPON): ").strip()
            if t:
                DEFAULT_ONU_TYPE = t
                print(f"OK. DEFAULT TYPE sekarang: {DEFAULT_ONU_TYPE}")
            continue

        if ch == "2":
            out_pass = show_authentication(z, olt_if)
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
            target = input("Masukkan TYPE yang mau dihapus (contoh GGCL-G99-): ").strip()
            if not target:
                print("TYPE kosong.")
                continue

            out_pass = show_authentication(z, olt_if)
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
            onu_type = input("Masukkan ONU TYPE baru (contoh GGCL-G99- / STICK-EPON-1P): ").strip()
            if not onu_type:
                print("TYPE kosong.")
                continue

            try:
                eth_ports = int(input("Jumlah Ethernet ports (contoh 1 / 2 / 4): ").strip() or "0")
                wifi_ssids = int(input("Jumlah WiFi SSIDs (contoh 0 / 4 / 8): ").strip() or "0")
                voip_ports = int(input("Jumlah VoIP ports (contoh 0 / 1 / 2): ").strip() or "0")
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
    print("1) List ONU UNAUTH (deny) + MAC/SN/MODEL  [CLEAR SCREEN]")
    print("2) AUTH PASS vs DENY                      [CLEAR SCREEN]")
    print("5) SMART Provision DENY (type trial sampai MAC hilang dari UNAUTH) + WR")
    print("6) Ganti interface (port OLT)")
    print("9) Count ONU terdaftar di SEMUA card/port (card=/2,/4; port=/1..8)")
    print("10) FORCE FIX DENY (rollback per ONU) + WR")
    print("11) SMART AUTO LOOP (multi-round sampai deny habis / max round) + WR")
    print("13) MODE TYPE (fallback / show / delete / tambah onu-type)")
    print("14) Edit VLAN ONU (APPEND/REPLACE) untuk ONU terpilih + WR")
    print("15) DELETE ALL ONU di port ini (PASS+DENY) + WR")
    print("0) Keluar")

# ================== MAIN ==================
def main():
    log_file = f"zxan_menu_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log = Logger(log_file)

    olt_if = input("Masukkan interface EPON OLT (contoh: epon-olt_1/4/8): ").strip()
    m = re.search(r"epon-olt_(\d+/\d+/\d+)", olt_if)
    if not m:
        print("Format salah. Contoh: epon-olt_1/4/8")
        return

    # onu_prefix ikut port aktif
    onu_prefix = f"epon-onu_{m.group(1)}:"

    z = ZXAN(HOST, PORT, log)
    try:
        z.login(USERNAME, PASSWORD)

        go_exec(z)
        z.send_wait_any("terminal length 0", 10, "paging-length0")
        z.send_wait_any("terminal page 0", 10, "paging-page0")

        print("\nMengambil daftar ONU TYPE dari running-config... (sekali saja)")
        log.silent = True
        try:
            available_types = get_available_onu_types(z)
        finally:
            log.silent = False

        print(f"Total TYPE ditemukan: {len(available_types)}")
        if available_types:
            print("Contoh TYPE:", ", ".join(available_types[:10]) + (" ..." if len(available_types) > 10 else ""))

        while True:
            menu()
            c = input(f"[{olt_if}] Pilih: ").strip()

            if c == "0":
                break

            if c == "6":
                olt_if_new = input("Masukkan interface baru (cth: epon-olt_1/4/8): ").strip()
                m2 = re.search(r"epon-olt_(\d+/\d+/\d+)", olt_if_new)
                if not m2:
                    print("Format salah.")
                    continue
                olt_if = olt_if_new
                onu_prefix = f"epon-onu_{m2.group(1)}:"
                print(f"OK. Interface aktif sekarang: {olt_if}")
                continue

            if c == "1":
                clear_screen()
                print(f"=== CEK UNAUTH/DENY [{olt_if}] ===\n")
                out = show_unauthentication(z, olt_if)
                deny = parse_unauthentication_blocks(out)
                print(f"\nAUTH DENY: {len(deny)} ONU")
                for d in deny:
                    print(f" - ONU {d.onu_no} | MAC {d.mac or '-'} | SN {d.sn or '-'} | MODEL {d.model or '-'}")
                continue

            if c == "2":
                clear_screen()
                print(f"=== CEK AUTH PASS vs DENY [{olt_if}] ===\n")

                out_pass = show_authentication(z, olt_if)
                passed = parse_authentication_blocks(out_pass)
                print(f"\nAUTH PASS: {len(passed)} ONU")
                for p in passed:
                    print(f" - ONU {p.onu_no} | TYPE {p.onu_type or '-'} | MgmtMAC {p.mgmt_mac or '-'} | LastAuth {p.last_auth_time or '-'}")

                out_deny = show_unauthentication(z, olt_if)
                deny = parse_unauthentication_blocks(out_deny)
                print(f"\nAUTH DENY: {len(deny)} ONU")
                for d in deny:
                    print(f" - ONU {d.onu_no} | MAC {d.mac or '-'} | SN {d.sn or '-'} | MODEL {d.model or '-'}")
                continue

            if c == "5":
                out = show_unauthentication(z, olt_if)
                denies = parse_unauthentication_blocks(out)
                if not denies:
                    print("Tidak ada ONU unauth/deny untuk diprovision.")
                    continue

                print("\nSMART Provision: per ONU coba type sampai MAC hilang dari UNAUTH.")
                confirm = input(f"Total DENY {len(denies)} ONU. Ketik YES: ").strip()
                if confirm != "YES":
                    print("Batal.")
                    continue

                ok_count = 0
                for d in denies:
                    if provision_one_deny_until_gone(z, olt_if, onu_prefix, d, available_types):
                        ok_count += 1

                end_wr(z)
                print(f"Provision selesai + WR. Sukses: {ok_count}/{len(denies)}")
                continue

            if c == "9":
                log.silent = True
                try:
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
                finally:
                    log.silent = False

                print("\nCOUNT ONU TERDAFTAR (SEMUA CARD/PORT):")
                for p, total, pcount, dcount in results:
                    print(f" - {p}: TOTAL {total} | PASS {pcount} | DENY {dcount}")
                print(f"\nGRAND TOTAL: {grand_total} | PASS {grand_pass} | DENY {grand_deny}")
                continue

            if c == "10":
                force_fix_deny_on_port(z, olt_if, onu_prefix)
                continue

            if c == "11":
                try:
                    mr = int(input(f"Max round (default {MAX_GLOBAL_ROUNDS}): ").strip() or str(MAX_GLOBAL_ROUNDS))
                except Exception:
                    mr = MAX_GLOBAL_ROUNDS
                confirm = input(f"SMART AUTO LOOP max {mr} round. Ketik YES: ").strip()
                if confirm != "YES":
                    print("Batal.")
                    continue
                smart_auto_provision_until_clear(z, olt_if, onu_prefix, available_types, mr)
                continue

            if c == "13":
                available_types = mode_type_menu(z, olt_if, available_types)
                continue

            if c == "14":
                s = input("Masukkan ONU ID (cth 22 / 1-8 / 1,3,5-7): ").strip()
                ids = parse_range_ids(s)
                if not ids:
                    print("Kosong.")
                    continue

                vlan_s = input("Masukkan VLAN (cth 16 / 16,52 / 16,52,1002): ").strip()
                vlans = parse_range_ids(vlan_s)
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

            print("Pilihan tidak dikenal.")

    finally:
        z.close()
        log.silent = False
        log.info(f"LOG FILE: {log_file}")

if __name__ == "__main__":
    main()
