#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AV/EDR detection on remote Windows hosts via LsarLookupNames and IPC$ named
pipe enumeration, with Bayesian evidence fusion, entropy-based pattern
scoring, and coverage-aware uncertainty quantification.

AUTHORIZED USE ONLY: For authorized security assessment and defensive
verification. Unauthorized access to computer systems is illegal.

"""

import argparse
import fnmatch
import json
import math
import os
import re
import signal
import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

IMPACKET_AVAILABLE = True
IMPACKET_ERROR = ""

try:
    from impacket.dcerpc.v5 import lsat, lsad, transport
    from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, RPC_UNICODE_STRING
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, DCERPCException
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5.transport import SMBTransport
except ImportError as _e:
    IMPACKET_AVAILABLE = False
    IMPACKET_ERROR = str(_e)


__tool_name__ = "SPECTRA"
__tool_fullname__ = "Threat Reconnaissance & Analysis"
__version__ = "1.0.0"

DEFAULT_TIMEOUT = 30
DEFAULT_THREADS = 5
DEFAULT_SMB_PORT = 445
MAX_RETRIES = 2
RETRY_DELAY = 1.5
EPSILON = 1e-9

NT_SERVICE_SID_PREFIX = "S-1-5-80-"
WELL_KNOWN_SIDS = {
    "S-1-0-0", "S-1-1-0", "S-1-2-0", "S-1-3-0", "S-1-5-7", "S-1-5-9",
    "S-1-5-10", "S-1-5-11", "S-1-5-12", "S-1-5-13", "S-1-5-14", "S-1-5-17",
    "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-32",
}

TIER_ORDER = {"enterprise_edr": 0, "advanced_av": 1, "basic_av": 2, "agent": 3, "unknown": 4}


class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for attr in ("RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "BOLD", "DIM", "RESET"):
            setattr(cls, attr, "")


class SecureLogger:
    _lock = None
    _verbose = False
    _debug = False
    _color = True
    _redaction_patterns = [
        (re.compile(r"(-p\s+)(\S+)"), r"\1[REDACTED]"),
        (re.compile(r"(--password[=\s])(\S+)"), r"\1[REDACTED]"),
        (re.compile(r"(--nthash[=\s])(\S+)"), r"\1[REDACTED]"),
        (re.compile(r"(--lmhash[=\s])(\S+)"), r"\1[REDACTED]"),
        (re.compile(r"(--aeskey[=\s])(\S+)"), r"\1[REDACTED]"),
        (re.compile(r"([Pp]assword[:\s=])(\S+)"), r"\1[REDACTED]"),
        (re.compile(r"([0-9a-f]{32})", re.IGNORECASE), lambda m: m.group(1)[:4] + "…" + m.group(1)[-4:]),
    ]

    def __init__(self):
        if SecureLogger._lock is None:
            SecureLogger._lock = threading.Lock()

    @classmethod
    def configure(cls, verbose=False, debug=False, color=True):
        cls._verbose = verbose
        cls._debug = debug
        cls._color = color
        if not color:
            C.disable()

    @classmethod
    def sanitize(cls, msg: str) -> str:
        for pattern, repl in cls._redaction_patterns:
            msg = pattern.sub(repl, msg)
        return msg

    @classmethod
    def _emit(cls, prefix, color, host, msg):
        msg = cls.sanitize(msg)
        if cls._lock:
            with cls._lock:
                ts = time.strftime("%H:%M:%S")
                c = C if cls._color else C()
                print(f"  {color}{prefix}{c.RESET} [{c.DIM}{ts}{c.RESET}] [{host}] {msg}", flush=True)

    @classmethod
    def info(cls, host, msg):
        cls._emit("*", C.CYAN, host, msg)

    @classmethod
    def success(cls, host, msg):
        cls._emit("+", C.GREEN, host, msg)

    @classmethod
    def error(cls, host, msg):
        cls._emit("-", C.RED, host, msg)

    @classmethod
    def found(cls, host, msg):
        cls._emit("!", C.YELLOW, host, msg)

    @classmethod
    def debug(cls, host, msg):
        if cls._debug:
            cls._emit("D", C.MAGENTA, host, msg)

    @classmethod
    def verbose(cls, host, msg):
        if cls._verbose:
            cls._emit("v", C.BLUE, host, msg)


class Validator:
    MAX_TARGETS = 10000
    MAX_FILE_BYTES = 1024 * 1024
    MAX_LINE_LENGTH = 512

    @staticmethod
    def validate_target(target: str) -> bool:
        if not target or len(target) > 253:
            return False
        try:
            socket.inet_aton(target)
            return True
        except (socket.error, OSError):
            pass
        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except (socket.error, OSError):
            pass
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$", target):
            return False
        for label in target.split("."):
            if not label or len(label) > 63:
                return False
        return True

    @staticmethod
    def validate_hash(value: str, label: str) -> str:
        if not value:
            return ""
        value = value.strip().lower()
        if not re.match(r"^[0-9a-f]{32}$", value):
            raise ValueError(f"Invalid {label}: expected 32 hexadecimal characters")
        return value

    @staticmethod
    def validate_range(name: str, value: int, lo: int, hi: int) -> int:
        if not isinstance(value, int) or value < lo or value > hi:
            raise ValueError(f"{name} must be an integer in [{lo}, {hi}], got {value}")
        return value

    @staticmethod
    def validate_file_path(path: str) -> str:
        if not path or "\x00" in path or len(path) > 4096:
            raise ValueError("Invalid file path")
        if ".." in path:
            raise ValueError("Path traversal rejected")
        resolved = os.path.realpath(path)
        if not os.path.isfile(resolved):
            raise FileNotFoundError(f"File not found: {path}")
        if not os.access(resolved, os.R_OK):
            raise PermissionError(f"File not readable: {path}")
        if os.path.getsize(resolved) > Validator.MAX_FILE_BYTES:
            raise ValueError(f"File exceeds {Validator.MAX_FILE_BYTES} byte limit")
        return resolved

    @staticmethod
    def validate_output_path(path: str) -> str:
        if not path or "\x00" in path or len(path) > 4096:
            raise ValueError("Invalid output path")
        if "\x00" in path:
            raise ValueError("Null byte in path")
        directory = os.path.dirname(os.path.abspath(path))
        if not os.path.isdir(directory):
            raise ValueError(f"Output directory does not exist: {directory}")
        return path


class SafeError:
    _patterns = [
        (re.compile(r"(connection\s+refused|timed?\s*out|unreachable)", re.I), "Connection failed (host unreachable or timed out)"),
        (re.compile(r"(access\s+denied|logon\s+failure|nt_status_access_denied)", re.I), "Authentication or access denied"),
        (re.compile(r"(name\s+or\s+service\s+not\s+known|getaddrinfo\s+failed|no\s+such\s+host)", re.I), "Hostname resolution failed"),
        (re.compile(r"(session\s+error|nt_status)", re.I), "SMB protocol error"),
        (re.compile(r"(broken\s+pipe|connection\s+reset)", re.I), "Connection dropped by remote host"),
    ]

    @classmethod
    def describe(cls, exc: Exception) -> str:
        for pattern, message in cls._patterns:
            if pattern.search(str(exc)):
                return message
        return "Operation failed"


class BayesianEngine:

    PRIOR_INSTALLED = 0.031
    P_RUNNING_GIVEN_INSTALLED = 0.93
    P_RUNNING_GIVEN_NOT_INSTALLED = 0.001

    LR_SERVICE_VALID_SID = 40.0
    LR_SERVICE_INVALID_SID = 2.0
    LR_SPECIFIC_PIPE_INSTALL = 8.0
    LR_GENERIC_PIPE_INSTALL = 2.0
    LR_SPECIFIC_PIPE_RUNNING = 15.0
    LR_GENERIC_PIPE_RUNNING = 3.0
    LR_NO_PIPE_FULL_COVERAGE = 0.15
    LR_NO_PIPE_NO_COVERAGE = 1.0

    @staticmethod
    def odds_update(prior: float, lr: float) -> float:
        prior = max(min(prior, 1.0 - EPSILON), EPSILON)
        lr = max(lr, EPSILON)
        odds = (prior / (1.0 - prior)) * lr
        posterior = odds / (1.0 + odds)
        return max(min(posterior, 1.0 - EPSILON), EPSILON)

    @classmethod
    def infer_installation(cls, evidence: List[Tuple[str, int]]) -> float:
        posterior = cls.PRIOR_INSTALLED
        for evidence_type, count in evidence:
            if evidence_type == "service_valid":
                lr = cls.LR_SERVICE_VALID_SID
            elif evidence_type == "service_invalid":
                lr = cls.LR_SERVICE_INVALID_SID
            elif evidence_type == "specific_pipe":
                lr = cls.LR_SPECIFIC_PIPE_INSTALL
            elif evidence_type == "generic_pipe":
                lr = cls.LR_GENERIC_PIPE_INSTALL
            else:
                continue
            for _ in range(min(count, 3)):
                posterior = cls.odds_update(posterior, lr)
        return posterior

    @classmethod
    def infer_running(cls, p_installed: float, pipe_evidence: str, pipe_count: int, coverage: float) -> float:
        if p_installed < 0.01:
            return cls.P_RUNNING_GIVEN_NOT_INSTALLED

        p_running_baseline = cls.P_RUNNING_GIVEN_INSTALLED * p_installed + cls.P_RUNNING_GIVEN_NOT_INSTALLED * (1.0 - p_installed)

        if pipe_evidence == "specific":
            lr = cls.LR_SPECIFIC_PIPE_RUNNING
        elif pipe_evidence == "generic":
            lr = cls.LR_GENERIC_PIPE_RUNNING
        elif pipe_evidence == "absent":
            if coverage < 0.3:
                lr = cls.LR_NO_PIPE_NO_COVERAGE
            else:
                effective = 1.0 + (cls.LR_NO_PIPE_FULL_COVERAGE - 1.0) * coverage
                lr = effective
        else:
            lr = 1.0

        return cls.odds_update(p_running_baseline, lr)

    @staticmethod
    def map_confidence(p: float) -> str:
        if p >= 0.90:
            return "HIGH"
        if p >= 0.50:
            return "MEDIUM"
        return "LOW"


class EntropyScorer:
    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @classmethod
    def pattern_specificity(cls, pattern: str) -> float:
        if not pattern:
            return 0.0
        literals = pattern.replace("*", "").replace("?", "")
        if not literals:
            return 0.0
        literal_ratio = len(literals) / len(pattern)
        length_score = min(len(literals) / 12.0, 1.0)
        entropy = cls.shannon_entropy(literals) / 4.0
        has_path = "\\" in pattern or "/" in pattern
        path_bonus = 0.15 if has_path else 0.0
        return min(literal_ratio * 0.35 + length_score * 0.35 + min(entropy, 1.0) * 0.20 + path_bonus, 1.0)


class CoverageAssessor:
    TYPICAL_VISIBLE_PIPES = 15
    MIN_NORMAL_PIPES = 8

    @classmethod
    def assess(cls, pipes_visible: int, enumeration_succeeded: bool) -> float:
        if not enumeration_succeeded:
            return 0.0
        if pipes_visible <= 0:
            return 0.05
        if pipes_visible < 3:
            return 0.25
        if pipes_visible < cls.MIN_NORMAL_PIPES:
            return 0.55
        if pipes_visible < cls.TYPICAL_VISIBLE_PIPES:
            return 0.85
        return 1.0


class PipeMatcher:
    GENERIC_PATTERNS = {"*", "*.*", "?*", "*_*", "**"}

    @staticmethod
    def normalize_pipe_name(name: str) -> str:
        if not name:
            return ""
        name = name.lstrip("\\/")
        if name.upper().startswith("PIPE\\"):
            name = name[5:]
        return name.lower()

    @staticmethod
    def normalize_pattern(pattern: str) -> str:
        if not pattern:
            return ""
        pattern = pattern.lstrip("\\/")
        if pattern.upper().startswith("PIPE\\"):
            pattern = pattern[5:]
        return pattern.lower()

    @classmethod
    def match(cls, pipe_name: str, pattern: str) -> bool:
        if not pipe_name or not pattern:
            return False
        norm_pattern = cls.normalize_pattern(pattern)
        if norm_pattern in cls.GENERIC_PATTERNS:
            return False
        return fnmatch.fnmatch(cls.normalize_pipe_name(pipe_name), norm_pattern)

    @classmethod
    def is_specific(cls, pattern: str) -> bool:
        return EntropyScorer.pattern_specificity(pattern) >= 0.45


class SIDValidator:
    @staticmethod
    def extract_sid_string(sid_obj) -> Optional[str]:
        if sid_obj is None:
            return None
        try:
            if hasattr(sid_obj, "formatCanonical"):
                return sid_obj.formatCanonical()
            if isinstance(sid_obj, str):
                return sid_obj
            return str(sid_obj)
        except Exception:
            return None

    @classmethod
    def is_nt_service_sid(cls, sid_str: Optional[str]) -> bool:
        if not sid_str:
            return False
        if sid_str in WELL_KNOWN_SIDS:
            return False
        return sid_str.startswith(NT_SERVICE_SID_PREFIX)


class HashNormalizer:
    LM_EMPTY = "aad3b435b51404eeaad3b435b51404ee"

    @classmethod
    def normalize(cls, lm_arg: str, nt_arg: str) -> Tuple[str, str]:
        lm, nt = "", ""
        if nt_arg:
            nt_arg = nt_arg.strip().lower()
            if ":" in nt_arg:
                parts = nt_arg.split(":", 1)
                lm = Validator.validate_hash(parts[0], "LM hash") if parts[0] else ""
                nt = Validator.validate_hash(parts[1], "NT hash") if parts[1] else ""
            else:
                nt = Validator.validate_hash(nt_arg, "NT hash")
        if lm_arg:
            lm_candidate = lm_arg.strip().lower()
            if lm_candidate and lm_candidate != cls.LM_EMPTY:
                lm = Validator.validate_hash(lm_candidate, "LM hash")
        return lm, nt


PRODUCTS = [
    {"name": "Windows Defender Antivirus", "tier": "basic_av",
     "services": [{"name": "WinDefend", "description": "Windows Defender Antivirus Service"},
                  {"name": "WdNisSvc", "description": "Windows Defender Network Inspection Service"},
                  {"name": "WdFilter", "description": "Windows Defender Filter Driver"}],
     "pipes": []},
    {"name": "Microsoft Defender for Endpoint", "tier": "enterprise_edr",
     "services": [{"name": "Sense", "description": "Windows Defender ATP"},
                  {"name": "SenseIR", "description": "Windows Defender ATP IR"},
                  {"name": "SenseCE", "description": "Windows Defender ATP CE"},
                  {"name": "SenseScanDriver", "description": "Windows Defender ATP Scan Driver"}],
     "pipes": []},
    {"name": "CrowdStrike Falcon", "tier": "enterprise_edr",
     "services": [{"name": "CSFalconService", "description": "CrowdStrike Falcon Sensor Service"}],
     "pipes": [{"name": "CrowdStrike\\{*", "processes": ["CSFalconContainer.exe", "CSFalconService.exe"]}]},
    {"name": "SentinelOne", "tier": "enterprise_edr",
     "services": [{"name": "SentinelAgent", "description": "SentinelOne Endpoint Protection Agent"},
                  {"name": "SentinelStaticEngine", "description": "SentinelOne Static Engine"},
                  {"name": "LogProcessorService", "description": "SentinelOne Log Processor"}],
     "pipes": [{"name": "SentinelAgentWorkerCert.*", "processes": []},
               {"name": "DFIScanner.Etw.*", "processes": ["SentinelStaticEngine.exe"]},
               {"name": "DFIScanner.Inline.*", "processes": ["SentinelAgent.exe"]}]},
    {"name": "Carbon Black App Control", "tier": "enterprise_edr",
     "services": [{"name": "Parity", "description": "Carbon Black App Control Agent"}],
     "pipes": []},
    {"name": "Carbon Black Cloud Sensor", "tier": "enterprise_edr",
     "services": [{"name": "CBDefense", "description": "Carbon Black Cloud Defense Sensor"},
                  {"name": "CbDefense", "description": "Carbon Black Cloud Defense Sensor"}],
     "pipes": [{"name": "CbDefenseEventPipe*", "processes": ["cbdefense.exe"]}]},
    {"name": "Cortex XDR", "tier": "enterprise_edr",
     "services": [{"name": "xdrhealth", "description": "Cortex XDR Health Helper"},
                  {"name": "cyserver", "description": "Cortex XDR Agent"},
                  {"name": "CyveraSvc", "description": "Cortex XDR Cyvera Service"}],
     "pipes": []},
    {"name": "Cybereason", "tier": "enterprise_edr",
     "services": [{"name": "CybereasonActiveProbe", "description": "Cybereason Active Probe"},
                  {"name": "CybereasonCRS", "description": "Cybereason Anti-Ransomware"},
                  {"name": "CybereasonBlocki", "description": "Cybereason Execution Prevention"}],
     "pipes": [{"name": "CybereasonAPConsoleMinionHostIpc_*", "processes": ["minionhost.exe"]},
               {"name": "CybereasonAPServerProxyIpc_*", "processes": ["minionhost.exe"]}]},
    {"name": "Trellix EDR", "tier": "enterprise_edr",
     "services": [{"name": "McAfee Endpoint Security Platform Service", "description": "Trellix Core Service"},
                  {"name": "mfemactl", "description": "Trellix Management Service"},
                  {"name": "mfemms", "description": "McAfee Management Service"},
                  {"name": "mfefire", "description": "Trellix Firewall Core Service"},
                  {"name": "masvc", "description": "Trellix Agent Service"},
                  {"name": "macmnsvc", "description": "Trellix Agent Common Service"},
                  {"name": "mfetp", "description": "Trellix Endpoint Threat Prevention"},
                  {"name": "mfewc", "description": "Trellix Endpoint Security Web Control"},
                  {"name": "mfeaack", "description": "Trellix Anti-Malware Core Service"}],
     "pipes": [{"name": "TrellixEDR_Pipe_*", "processes": ["McAfeeEDR.exe"]},
               {"name": "mfemactl_*", "processes": ["mfemactl.exe"]},
               {"name": "mfefire_*", "processes": ["mfefire.exe"]},
               {"name": "McAfeeAgent_Pipe_*", "processes": ["McAfeeAgent.exe"]},
               {"name": "mfetp_*", "processes": ["mfetp.exe"]}]},
    {"name": "Trend Micro Endpoint Security", "tier": "advanced_av",
     "services": [{"name": "Trend Micro Endpoint Basecamp", "description": "Trend Micro Endpoint Basecamp"},
                  {"name": "TMBMServer", "description": "Trend Micro Unauthorized Change Prevention"},
                  {"name": "Trend Micro Web Service Communicator", "description": "Trend Micro Web Service Communicator"},
                  {"name": "TMiACAgentSvc", "description": "Trend Micro Application Control"},
                  {"name": "CETASvc", "description": "Trend Micro Cloud Endpoint Telemetry"},
                  {"name": "iVPAgent", "description": "Trend Micro Vulnerability Protection"},
                  {"name": "ds_agent", "description": "Trend Micro Deep Security Agent"},
                  {"name": "ds_monitor", "description": "Trend Micro Deep Security Monitor"},
                  {"name": "ds_notifier", "description": "Trend Micro Deep Security Notifier"}],
     "pipes": [{"name": "IPC_XBC_XBC_AGENT_PIPE_*", "processes": ["EndpointBasecamp.exe"]},
               {"name": "iacagent_*", "processes": ["TMiACAgentSvc.exe"]},
               {"name": "OIPC_LWCS_PIPE_*", "processes": ["TmListen.exe"]},
               {"name": "OIPC_NTRTSCAN_PIPE_*", "processes": ["Ntrtscan.exe"]}]},
    {"name": "Sophos Intercept X", "tier": "enterprise_edr",
     "services": [{"name": "SntpService", "description": "Sophos Network Threat Protection"},
                  {"name": "Sophos Endpoint Defense Service", "description": "Sophos Endpoint Defense Service"},
                  {"name": "Sophos File Scanner Service", "description": "Sophos File Scanner Service"},
                  {"name": "Sophos Health Service", "description": "Sophos Health Service"},
                  {"name": "Sophos Live Query", "description": "Sophos Live Query"},
                  {"name": "Sophos Managed Threat Response", "description": "Sophos MTR"},
                  {"name": "Sophos MCS Agent", "description": "Sophos MCS Agent"},
                  {"name": "Sophos MCS Client", "description": "Sophos MCS Client"},
                  {"name": "Sophos System Protection Service", "description": "Sophos System Protection"}],
     "pipes": [{"name": "SophosUI", "processes": []},
               {"name": "SophosEventStore", "processes": []},
               {"name": "sophos_deviceencryption", "processes": []},
               {"name": "sophoslivequery_*", "processes": []}]},
    {"name": "Symantec Endpoint Protection", "tier": "advanced_av",
     "services": [{"name": "SepMasterService", "description": "Symantec Endpoint Protection"},
                  {"name": "SepScanService", "description": "Symantec Endpoint Protection Scan"},
                  {"name": "SNAC", "description": "Symantec Network Access Control"}],
     "pipes": []},
    {"name": "Kaspersky Security for Windows Server", "tier": "advanced_av",
     "services": [{"name": "kavfsslp", "description": "Kaspersky Security Exploit Prevention"},
                  {"name": "KAVFS", "description": "Kaspersky Security Service"},
                  {"name": "KAVFSGT", "description": "Kaspersky Security Management"},
                  {"name": "klnagent", "description": "Kaspersky Security Center"}],
     "pipes": [{"name": "Exploit_Blocker", "processes": ["kavfswh.exe"]}]},
    {"name": "ESET", "tier": "advanced_av",
     "services": [{"name": "ekm", "description": "ESET Kernel Service"},
                  {"name": "epfw", "description": "ESET Personal Firewall"},
                  {"name": "epfwlwf", "description": "ESET LightWeight Filter"},
                  {"name": "epfwwfp", "description": "ESET Windows Filtering Platform"},
                  {"name": "EraAgentSvc", "description": "ESET Management Agent service"},
                  {"name": "ERAAgent", "description": "ESET Management Agent service"},
                  {"name": "efwd", "description": "ESET Communication Forwarding Service"},
                  {"name": "ehttpsrv", "description": "ESET HTTP Server"}],
     "pipes": [{"name": "nod_scriptmon_pipe", "processes": []}]},
    {"name": "Bitdefender", "tier": "advanced_av",
     "services": [{"name": "bdredline_agent", "description": "Bitdefender Agent RedLine Service"},
                  {"name": "BDAuxSrv", "description": "Bitdefender Auxiliary Service"},
                  {"name": "UPDATESRV", "description": "Bitdefender Desktop Update Service"},
                  {"name": "VSSERV", "description": "Bitdefender Virus Shield"},
                  {"name": "bdredline", "description": "Bitdefender RedLine Service"},
                  {"name": "EPRedline", "description": "Bitdefender Endpoint Redline Service"},
                  {"name": "EPUpdateService", "description": "Bitdefender Endpoint Update Service"},
                  {"name": "EPSecurityService", "description": "Bitdefender Endpoint Security Service"},
                  {"name": "EPProtectedService", "description": "Bitdefender Endpoint Protected Service"},
                  {"name": "EPIntegrationService", "description": "Bitdefender Endpoint Integration Service"}],
     "pipes": [{"name": "\\bdConnector\\ServiceControl\\EPSecurityService.exe", "processes": ["EPConsole.exe"]},
               {"name": "etw_sensor_pipe_ppl", "processes": ["EPProtectedService.exe"]},
               {"name": "local\\msgbus\\antitracker.low\\*", "processes": ["bdagent.exe"]},
               {"name": "local\\msgbus\\aspam.actions.low\\*", "processes": ["bdagent.exe"]},
               {"name": "local\\msgbus\\bd.process.broker.pipe", "processes": ["bdagent.exe", "bdservicehost.exe"]},
               {"name": "local\\msgbus\\bdagent*", "processes": ["bdagent.exe"]},
               {"name": "local\\msgbus\\bdauxsrv", "processes": ["bdagent.exe", "bdntwrk.exe"]}]},
    {"name": "FortiClient", "tier": "advanced_av",
     "services": [{"name": "FA_Scheduler", "description": "FortiClient Service Scheduler"},
                  {"name": "FCT_SecSvr", "description": "FortiClient Endpoint Protected Process"}],
     "pipes": [{"name": "FortiClient_DBLogDaemon", "processes": ["FCDBLog.exe"]},
               {"name": "FC_*", "processes": ["FortiTray.exe"]}]},
    {"name": "FortiEDR", "tier": "enterprise_edr",
     "services": [{"name": "FortiEDR Collector Service", "description": "Fortinet EDR Collector"}],
     "pipes": []},
    {"name": "Malwarebytes", "tier": "advanced_av",
     "services": [{"name": "MBAMService", "description": "Malwarebytes Service"},
                  {"name": "MBEndpointAgent", "description": "Malwarebytes Cloud Endpoint Agent"}],
     "pipes": [{"name": "MBLG", "processes": ["MBAMService.exe"]},
               {"name": "MBEA2_R", "processes": ["MBCloudEA.exe"]},
               {"name": "MBEA2_W", "processes": ["MBCloudEA.exe"]}]},
    {"name": "Panda Adaptive Defense 360", "tier": "enterprise_edr",
     "services": [{"name": "PandaAetherAgent", "description": "Panda Endpoint Agent"},
                  {"name": "PSUAService", "description": "Panda Product Service"},
                  {"name": "NanoServiceMain", "description": "Panda Cloud Antivirus Service"}],
     "pipes": [{"name": "NNS_API_IPC_SRV_ENDPOINT", "processes": ["PSANHost.exe"]},
               {"name": "PSANMSrvcPpal", "processes": ["PSUAService.exe"]}]},
    {"name": "WithSecure Elements", "tier": "advanced_av",
     "services": [{"name": "fsdevcon", "description": "WithSecure Device Control"},
                  {"name": "fshoster", "description": "WithSecure Hoster"},
                  {"name": "fsnethoster", "description": "WithSecure Hoster (Restricted)"},
                  {"name": "fsulhoster", "description": "WithSecure Ultralight Hoster"},
                  {"name": "fsulnethoster", "description": "WithSecure Ultralight Network Hoster"},
                  {"name": "fsulprothoster", "description": "WithSecure Ultralight Protected Hoster"},
                  {"name": "wsulavprohoster", "description": "WithSecure Ultralight Protected AV"}],
     "pipes": [{"name": "FS_CCFIPC_*", "processes": ["fsatpn.exe", "fsatpl.exe", "fshoster32.exe", "fsulprothoster.exe", "fshoster64.exe", "FsPisces.exe"]}]},
    {"name": "G DATA Security Client", "tier": "advanced_av",
     "services": [{"name": "AVKWCtl", "description": "Anti-virus Kit Window Control"},
                  {"name": "AVKProxy", "description": "G Data AntiVirus Proxy Service"},
                  {"name": "GDScan", "description": "G Data AntiVirus Scan Service"}],
     "pipes": [{"name": "exploitProtectionIPC", "processes": ["AVKWCtlx64.exe"]}]},
    {"name": "Avast / AVG", "tier": "basic_av",
     "services": [{"name": "AvastWscReporter", "description": "Avast WSC Reporter Service"},
                  {"name": "aswbIDSAgent", "description": "Avast IDS Agent Service"},
                  {"name": "AVGWscReporter", "description": "AVG WSC Reporter Service"},
                  {"name": "avgbIDSAgent", "description": "AVG IDS Agent Service"}],
     "pipes": [{"name": "aswCallbackPipe*", "processes": ["AvastSvc.exe", "aswEngSrv.exe"]},
               {"name": "avgCallbackPipe*", "processes": ["AVGSvc.exe", "aswEngSrv.exe"]}]},
    {"name": "Check Point Endpoint Security", "tier": "enterprise_edr",
     "services": [{"name": "CPDA", "description": "Check Point Endpoint Agent"},
                  {"name": "vsmon", "description": "Check Point Network Protection"},
                  {"name": "CPFileAnlyz", "description": "Check Point File Analyzer"},
                  {"name": "EPClientUIService", "description": "Check Point Client UI"}],
     "pipes": []},
    {"name": "Cynet", "tier": "enterprise_edr",
     "services": [{"name": "CynetLauncher", "description": "CynetLauncher"}],
     "pipes": []},
    {"name": "Elastic Defend", "tier": "enterprise_edr",
     "services": [{"name": "Elastic Agent", "description": "Elastic Agent Service"},
                  {"name": "ElasticEndpoint", "description": "Elastic Endpoint Security Service"}],
     "pipes": [{"name": "ElasticEndpointServiceComms-*", "processes": ["elastic-endpoint.exe"]},
               {"name": "elastic-agent-system", "processes": ["elastic-agent.exe"]}]},
    {"name": "Rapid7 Insight Agent", "tier": "agent",
     "services": [{"name": "ir_agent", "description": "Rapid7 Insight Agent"}],
     "pipes": []},
    {"name": "Wazuh", "tier": "agent",
     "services": [{"name": "WazuhSvc", "description": "Wazuh Windows Agent"}],
     "pipes": []},
    {"name": "Ivanti Security Controls", "tier": "agent",
     "services": [{"name": "STAgent$Shavlik Protect", "description": "Ivanti Security Controls Agent"},
                  {"name": "STDispatch$Shavlik Protect", "description": "Ivanti Security Controls Dispatcher"}],
     "pipes": []},
    {"name": "HarfangLab Hurukai EDR", "tier": "enterprise_edr",
     "services": [{"name": "hurukai", "description": "HarfangLab Hurukai Agent"},
                  {"name": "Hurukai agent", "description": "HarfangLab Hurukai Agent Service"},
                  {"name": "HarfangLab Hurukai agent", "description": "HarfangLab Hurukai Agent Program"},
                  {"name": "hurukai-av", "description": "HarfangLab Hurukai Antivirus"},
                  {"name": "hurukai-ui", "description": "HarfangLab Hurukai UI"}],
     "pipes": [{"name": "hurukai-control", "processes": ["hurukai.exe"]},
               {"name": "hurukai-servicing", "processes": ["hurukai.exe"]},
               {"name": "hurukai-amsi", "processes": ["hurukai.exe"]}]},
    {"name": "Acronis Cyber Protect", "tier": "advanced_av",
     "services": [{"name": "AcronisActiveProtectionService", "description": "Acronis Active Protection Service"}],
     "pipes": []},
    {"name": "BlackBerry CylancePROTECT", "tier": "enterprise_edr",
     "services": [{"name": "CylanceProtect", "description": "CylancePROTECT Service"},
                  {"name": "CylanceOptics", "description": "CylanceOPTICS Service"},
                  {"name": "CylanceSvc", "description": "Cylance Service"}],
     "pipes": []},
    {"name": "OpenEDR (Comodo)", "tier": "enterprise_edr",
     "services": [{"name": "edrsvc", "description": "OpenEDR Agent Service"},
                  {"name": "ComodoEDRAgent", "description": "Comodo EDR Agent"}],
     "pipes": []},
]

STRONG_PIPE_PRODUCTS = {
    "CrowdStrike Falcon", "SentinelOne", "Carbon Black App Control",
    "Cortex XDR", "Cybereason", "Elastic Defend", "Cynet",
}


def validate_products() -> List[str]:
    issues = []
    seen = set()
    for i, prod in enumerate(PRODUCTS):
        name = prod.get("name", "")
        if not name:
            issues.append(f"PRODUCTS[{i}]: missing name")
            continue
        if name in seen:
            issues.append(f"PRODUCTS[{i}]: duplicate name '{name}'")
        seen.add(name)
        for key in ("services", "pipes"):
            if key not in prod or not isinstance(prod[key], list):
                issues.append(f"'{name}': missing or invalid '{key}'")
                prod[key] = []
        for j, svc in enumerate(prod["services"]):
            if not isinstance(svc, dict) or "name" not in svc:
                issues.append(f"'{name}' services[{j}]: missing name")
        for j, pipe in enumerate(prod["pipes"]):
            if not isinstance(pipe, dict) or "name" not in pipe:
                issues.append(f"'{name}' pipes[{j}]: missing name")
            elif "processes" not in pipe:
                pipe["processes"] = []
    return issues


class SMBSession:
    def __init__(self, target_ip, username, password, domain, lm, nt, aes_key,
                 do_kerberos, kdc_host, port, timeout):
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.lm = lm
        self.nt = nt
        self.aes_key = aes_key
        self.do_kerberos = do_kerberos
        self.kdc_host = kdc_host
        self.port = port
        self.timeout = timeout
        self._smb = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def connect(self):
        try:
            self._smb = SMBConnection(self.target_ip, self.target_ip,
                                      sess_port=self.port, timeout=self.timeout)
            if self.do_kerberos:
                self._smb.kerberosLogin(self.username, self.password, self.domain,
                                        self.lm, self.nt, self.aes_key, self.kdc_host)
            else:
                self._smb.login(self.username, self.password, self.domain, self.lm, self.nt)
        except Exception as e:
            self._smb = None
            raise ConnectionError(SafeError.describe(e)) from e

    def close(self):
        if self._smb is not None:
            try:
                self._smb.logoff()
            except Exception:
                pass
            self._smb = None

    @property
    def smb(self):
        if self._smb is None:
            raise RuntimeError("SMB session not established")
        return self._smb

    def build_dce(self):
        dce_transport = SMBTransport(self.target_ip, filename=r"\lsarpc", smb_connection=self._smb)
        dce = dce_transport.get_dce_rpc()
        if self.do_kerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.bind(lsat.MSRPC_UUID_LSAT)
        return dce


class LSADetector:
    def __init__(self, dce, target_ip):
        self.dce = dce
        self.target_ip = target_ip
        self._policy_handle = None

    def _open_policy(self):
        req = lsad.LsarOpenPolicy2()
        req["SystemName"] = NULL
        req["ObjectAttributes"]["RootDirectory"] = NULL
        req["ObjectAttributes"]["ObjectName"] = NULL
        req["ObjectAttributes"]["SecurityDescriptor"] = NULL
        req["ObjectAttributes"]["SecurityQualityOfService"] = NULL
        req["DesiredAccess"] = MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES
        resp = self.dce.request(req)
        self._policy_handle = resp["PolicyHandle"]
        return self._policy_handle

    def _lookup_name(self, service_name: str) -> Tuple[bool, Optional[str]]:
        if self._policy_handle is None:
            self._open_policy()
        req = lsat.LsarLookupNames()
        req["PolicyHandle"] = self._policy_handle
        req["Count"] = 1
        name = RPC_UNICODE_STRING()
        name["Data"] = f"NT Service\\{service_name}"
        req["Names"].append(name)
        req["TranslatedSids"]["Sids"] = NULL
        req["LookupLevel"] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        try:
            resp = self.dce.request(req)
        except DCERPCException as e:
            err_str = str(e).upper()
            if "STATUS_NONE_MAPPED" in err_str or "STATUS_NO_MORE_ENTRIES" in err_str:
                return False, None
            if "ACCESS_DENIED" in err_str:
                raise PermissionError(SafeError.describe(e)) from e
            Logger_ref.debug(self.target_ip, f"RPC error: {SafeError.describe(e)}")
            return False, None
        except Exception as e:
            Logger_ref.debug(self.target_ip, f"Unexpected: {SafeError.describe(e)}")
            return False, None

        mapped_count = None
        try:
            mapped_count = resp["MappedCount"]
        except (KeyError, TypeError):
            pass

        sid_str = None
        try:
            sids = resp["TranslatedSids"]["Sids"]
            if sids:
                for entry in sids:
                    if hasattr(entry, "Sid") and entry["Sid"]:
                        sid_str = SIDValidator.extract_sid_string(entry["Sid"])
                        break
        except (KeyError, TypeError, IndexError):
            pass

        if mapped_count is not None and mapped_count == 0:
            return False, None
        return True, sid_str

    def scan(self) -> Dict[str, Dict]:
        results = {}
        self._open_policy()
        Logger_ref.info(self.target_ip, "LSA policy opened, scanning services")
        for product in PRODUCTS:
            for svc in product["services"]:
                try:
                    found, sid = self._lookup_name(svc["name"])
                    if found:
                        sid_valid = SIDValidator.is_nt_service_sid(sid)
                        entry = results.setdefault(product["name"], {"services": [], "sids": {}})
                        entry["services"].append(svc)
                        if sid:
                            entry["sids"][svc["name"]] = {"sid": sid, "valid": sid_valid}
                        Logger_ref.verbose(self.target_ip, f"Service: {svc['name']} valid_sid={sid_valid}")
                except PermissionError:
                    raise
                except Exception as e:
                    Logger_ref.debug(self.target_ip, f"Lookup: {SafeError.describe(e)}")
        return results


class PipeDetector:
    def __init__(self, smb_conn, target_ip):
        self.smb = smb_conn
        self.target_ip = target_ip

    def _list_pipes(self) -> List[str]:
        pipes = []
        try:
            for f in self.smb.listPath("IPC$", "\\*"):
                name = f.get_longname()
                if name in (".", ".."):
                    continue
                try:
                    if hasattr(f, "is_directory") and f.is_directory():
                        continue
                except Exception:
                    pass
                pipes.append(name)
        except Exception as e:
            raise ConnectionError(SafeError.describe(e)) from e
        return pipes

    def scan(self) -> Tuple[Dict[str, Dict], int, bool]:
        results = {}
        Logger_ref.info(self.target_ip, "Enumerating IPC$ named pipes")
        enumeration_succeeded = True
        try:
            available_pipes = self._list_pipes()
        except ConnectionError:
            enumeration_succeeded = False
            available_pipes = []
        Logger_ref.verbose(self.target_ip, f"Visible pipes: {len(available_pipes)}")
        for pipe_name in available_pipes:
            for product in PRODUCTS:
                for pipe_sig in product["pipes"]:
                    if PipeMatcher.match(pipe_name, pipe_sig["name"]):
                        specificity = EntropyScorer.pattern_specificity(pipe_sig["name"])
                        specific = specificity >= 0.45
                        entry = results.setdefault(product["name"], {"pipes": []})
                        entry["pipes"].append({
                            "pattern": pipe_sig["name"],
                            "matched": pipe_name,
                            "processes": pipe_sig.get("processes", []),
                            "specific": specific,
                            "specificity": round(specificity, 3),
                        })
        return results, len(available_pipes), enumeration_succeeded


class InferenceEngine:

    @staticmethod
    def correlate(service_results: Dict, pipe_results: Dict,
                  pipes_visible: int, enumeration_succeeded: bool) -> Tuple[Dict, float]:
        coverage = CoverageAssessor.assess(pipes_visible, enumeration_succeeded)
        all_products = set(service_results.keys()) | set(pipe_results.keys())
        merged = {}

        for product_name in all_products:
            svc_data = service_results.get(product_name, {})
            pipe_data = pipe_results.get(product_name, {})
            services = svc_data.get("services", [])
            sids = svc_data.get("sids", {})
            pipes = pipe_data.get("pipes", [])

            valid_sid_count = sum(1 for s in sids.values() if s.get("valid", False))
            invalid_sid_count = sum(1 for s in sids.values() if not s.get("valid", False))
            specific_pipes = [p for p in pipes if p.get("specific", False)]
            generic_pipes = [p for p in pipes if not p.get("specific", False)]

            install_evidence = []
            if valid_sid_count > 0:
                install_evidence.append(("service_valid", valid_sid_count))
            if invalid_sid_count > 0:
                install_evidence.append(("service_invalid", invalid_sid_count))
            if specific_pipes:
                install_evidence.append(("specific_pipe", len(specific_pipes)))
            if generic_pipes:
                install_evidence.append(("generic_pipe", len(generic_pipes)))

            p_installed = BayesianEngine.infer_installation(install_evidence)

            if specific_pipes:
                pipe_evidence = "specific"
            elif generic_pipes:
                pipe_evidence = "generic"
            elif enumeration_succeeded and not pipes:
                pipe_evidence = "absent"
            else:
                pipe_evidence = "unknown"

            p_running = BayesianEngine.infer_running(p_installed, pipe_evidence,
                                                     len(pipes), coverage)

            tier = "unknown"
            for prod in PRODUCTS:
                if prod["name"] == product_name:
                    tier = prod.get("tier", "unknown")
                    break

            if services and pipes:
                status = "INSTALLED and RUNNING"
            elif services and p_running >= 0.85:
                status = "INSTALLED (running inferred from baseline)"
            elif services:
                status = "INSTALLED (running state uncertain)"
            elif pipes and specific_pipes:
                status = "RUNNING (specific pipe)"
            elif pipes:
                status = "RUNNING (generic pipe, weak)"
            else:
                status = "UNCERTAIN"

            confidence = BayesianEngine.map_confidence(p_running) if p_installed >= 0.5 else "LOW"

            merged[product_name] = {
                "status": status,
                "confidence": confidence,
                "tier": tier,
                "p_installed": round(p_installed, 4),
                "p_running": round(p_running, 4),
                "coverage": coverage,
                "services": services,
                "sids": sids,
                "pipes": pipes,
            }

        return merged, coverage


Logger_ref = SecureLogger


def print_host_results(target_ip: str, results: Dict, coverage: float):
    print()
    if not results:
        SecureLogger.found(target_ip, "No AV/EDR products detected")
        return

    cov_note = ""
    if coverage < 0.3:
        cov_note = f" {C.RED}[IPC$ coverage degraded: {coverage:.0%}]{C.RESET}"
    elif coverage < 0.6:
        cov_note = f" {C.YELLOW}[IPC$ coverage partial: {coverage:.0%}]{C.RESET}"

    if cov_note:
        SecureLogger.info(target_ip, cov_note.strip())

    conf_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    tier_order = TIER_ORDER
    sorted_results = sorted(
        results.items(),
        key=lambda x: (conf_order.get(x[1].get("confidence", "LOW"), 3),
                       tier_order.get(x[1].get("tier", "unknown"), 4), x[0])
    )

    for product_name, data in sorted_results:
        confidence = data["confidence"]
        p_run = data["p_running"]
        p_inst = data["p_installed"]
        tier = data.get("tier", "unknown")
        conf_color = C.GREEN if confidence == "HIGH" else (C.YELLOW if confidence == "MEDIUM" else C.RED)
        SecureLogger.found(target_ip,
            f"{C.BOLD}{product_name}{C.RESET} [{conf_color}{confidence}{C.RESET}] "
            f"P(inst)={p_inst:.2f} P(run)={p_run:.2f} ({tier}) — {data['status']}")
        if data.get("services"):
            for svc in data["services"]:
                sid_data = data.get("sids", {}).get(svc["name"])
                sid_info = ""
                if sid_data:
                    mark = "+" if sid_data.get("valid") else "-"
                    sid_info = f" {C.DIM}[{mark}]{C.RESET}"
                print(f"         svc : {svc['name']} — {svc.get('description', '')}{sid_info}")
        if data.get("pipes"):
            for p in data["pipes"]:
                procs = ", ".join(p["processes"]) if p.get("processes") else "unknown"
                spec_mark = "*" if p.get("specific") else " "
                spec_score = p.get("specificity", 0)
                print(f"         pipe{spec_mark}: {p['matched']}  "
                      f"(specificity={spec_score:.2f}; likely: {procs})")
    print()


def export_json(all_results: Dict, output_file: str):
    try:
        serializable = {}
        for ip, (results, coverage) in all_results.items():
            serializable[ip] = {"coverage": coverage, "products": {}}
            for product, data in results.items():
                serializable[ip]["products"][product] = {
                    "status": data.get("status"),
                    "confidence": data.get("confidence"),
                    "tier": data.get("tier"),
                    "p_installed": data.get("p_installed"),
                    "p_running": data.get("p_running"),
                    "services": [{"name": s.get("name"), "description": s.get("description")}
                                 for s in data.get("services", [])],
                    "sids": data.get("sids", {}),
                    "pipes": [{"pattern": p.get("pattern"), "matched": p.get("matched"),
                               "specificity": p.get("specificity"),
                               "processes": p.get("processes", [])}
                              for p in data.get("pipes", [])],
                }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2, ensure_ascii=False)
        print(f"\n{C.GREEN}[+]{C.RESET} Results exported to {output_file}")
    except Exception as e:
        print(f"\n{C.RED}[-]{C.RESET} Export failed: {SafeError.describe(e)}", file=sys.stderr)


def scan_host(target_ip, username, password, domain, lm, nt, aes_key,
              do_kerberos, kdc_host, port, timeout, max_retries):
    print(f"\n{C.BOLD}{'─' * 60}{C.RESET}")
    print(f"  Target : {target_ip}")
    print(f"{'─' * 60}{C.RESET}")

    for attempt in range(1, max_retries + 1):
        try:
            with SMBSession(target_ip, username, password, domain, lm, nt,
                          aes_key, do_kerberos, kdc_host, port, timeout) as session:
                SecureLogger.success(target_ip, f"Authenticated as {domain}\\{username}" if domain else f"Authenticated as {username}")

                service_results = {}
                try:
                    dce = session.build_dce()
                    try:
                        lsa = LSADetector(dce, target_ip)
                        service_results = lsa.scan()
                    finally:
                        try:
                            dce.disconnect()
                        except Exception:
                            pass
                except PermissionError as e:
                    SecureLogger.error(target_ip, str(e))
                except Exception as e:
                    SecureLogger.error(target_ip, f"LSA/RPC: {SafeError.describe(e)}")

                pipe_results = {}
                pipes_visible = 0
                enumeration_succeeded = False
                try:
                    pd = PipeDetector(session.smb, target_ip)
                    pipe_results, pipes_visible, enumeration_succeeded = pd.scan()
                except ConnectionError as e:
                    SecureLogger.error(target_ip, f"Pipes: {str(e)}")
                except Exception as e:
                    SecureLogger.error(target_ip, f"Pipes: {SafeError.describe(e)}")

                results, coverage = InferenceEngine.correlate(service_results, pipe_results,
                                                               pipes_visible, enumeration_succeeded)
                print_host_results(target_ip, results, coverage)
                return results, coverage

        except ConnectionError as e:
            if attempt < max_retries:
                SecureLogger.verbose(target_ip, f"Retry {attempt}/{max_retries}")
                time.sleep(RETRY_DELAY)
            else:
                SecureLogger.error(target_ip, str(e))
        except KeyboardInterrupt:
            raise
        except Exception as e:
            SecureLogger.error(target_ip, SafeError.describe(e))
            break

    print_host_results(target_ip, {}, 0.0)
    return {}, 0.0


def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗  █████╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝███████║
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║██║  ██║
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝{C.RESET}
  {C.BOLD}Threat Reconnaissance & Analysis{C.RESET}
  {C.DIM}v{__version__} | Bayesian evidence fusion + coverage-aware inference{C.RESET}
  {C.RED}AUTHORIZED USE ONLY{C.RESET}
""")


def load_targets(target_file: str) -> List[str]:
    resolved = Validator.validate_file_path(target_file)
    targets = []
    seen = set()
    with open(resolved, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            if lineno > Validator.MAX_TARGETS:
                print(f"{C.YELLOW}[!]{C.RESET} Target limit reached at line {lineno}", file=sys.stderr)
                break
            line = line.strip()[:Validator.MAX_LINE_LENGTH]
            if not line or line.startswith("#"):
                continue
            if not Validator.validate_target(line):
                print(f"{C.YELLOW}[!]{C.RESET} Invalid target line {lineno}: {SecureLogger.sanitize(line)}", file=sys.stderr)
                continue
            if line not in seen:
                targets.append(line)
                seen.add(line)
    return targets


def parse_args():
    parser = argparse.ArgumentParser(
        prog=__tool_name__,
        description=f"{__tool_fullname__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    tg = parser.add_mutually_exclusive_group(required=True)
    tg.add_argument("-t", "--target", help="Single target IP or hostname")
    tg.add_argument("-T", "--targets", help="File with one target per line")
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("-u", "--username", required=True, help="Username")
    auth.add_argument("-d", "--domain", default="", help="Domain")
    auth.add_argument("-p", "--password", default="", help="Password")
    auth.add_argument("--lmhash", default="", help="LM hash")
    auth.add_argument("--nthash", default="", help="NT hash or LM:NT")
    auth.add_argument("--aeskey", default="", help="AES key for Kerberos")
    kerb = parser.add_argument_group("Kerberos")
    kerb.add_argument("--kerberos", action="store_true", help="Use Kerberos")
    kerb.add_argument("--kdchost", default="", help="KDC IP")
    conn = parser.add_argument_group("Connection")
    conn.add_argument("--port", type=int, default=DEFAULT_SMB_PORT)
    conn.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    conn.add_argument("--retries", type=int, default=MAX_RETRIES)
    conn.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    out = parser.add_argument_group("Output")
    out.add_argument("-v", "--verbose", action="store_true")
    out.add_argument("--debug", action="store_true")
    out.add_argument("--no-color", action="store_true")
    out.add_argument("--json", metavar="FILE")
    return parser.parse_args()


def main():
    if not IMPACKET_AVAILABLE:
        print(f"{C.RED}[!]{C.RESET} impacket is required: pip install impacket", file=sys.stderr)
        sys.exit(2)

    args = parse_args()

    try:
        port = Validator.validate_range("port", args.port, 1, 65535)
        timeout = Validator.validate_range("timeout", args.timeout, 1, 600)
        retries = Validator.validate_range("retries", args.retries, 0, 10)
        threads = Validator.validate_range("threads", args.threads, 1, 100)
    except ValueError as e:
        print(f"{C.RED}[!]{C.RESET} {e}", file=sys.stderr)
        sys.exit(1)

    use_color = not args.no_color and sys.stdout.isatty()
    SecureLogger.configure(verbose=args.verbose, debug=args.debug, color=use_color)
    global Logger_ref
    Logger_ref = SecureLogger

    print_banner()

    product_issues = validate_products()
    if product_issues:
        for issue in product_issues[:5]:
            print(f"{C.YELLOW}[!]{C.RESET} DB: {issue}", file=sys.stderr)

    if args.target:
        if not Validator.validate_target(args.target):
            print(f"{C.RED}[!]{C.RESET} Invalid target format", file=sys.stderr)
            sys.exit(1)
        targets = [args.target]
    else:
        try:
            targets = load_targets(args.targets)
        except (ValueError, FileNotFoundError, PermissionError) as e:
            print(f"{C.RED}[!]{C.RESET} {e}", file=sys.stderr)
            sys.exit(1)
        if not targets:
            print(f"{C.RED}[!]{C.RESET} No valid targets", file=sys.stderr)
            sys.exit(1)

    try:
        lm, nt = HashNormalizer.normalize(args.lmhash, args.nthash)
    except ValueError as e:
        print(f"{C.RED}[!]{C.RESET} {e}", file=sys.stderr)
        sys.exit(1)

    if args.kerberos and not args.domain:
        print(f"{C.RED}[!]{C.RESET} Kerberos requires --domain", file=sys.stderr)
        sys.exit(1)
    if not args.password and not nt and not args.aeskey:
        print(f"{C.RED}[!]{C.RESET} No authentication credential provided", file=sys.stderr)
        sys.exit(1)

    auth_method = "Kerberos" if args.kerberos else "NTLM"
    cred_method = "hash" if nt else ("AES key" if args.aeskey else "password")
    print(f"  {C.BOLD}Configuration{C.RESET}")
    print(f"  Targets : {len(targets)}")
    print(f"  User    : {args.domain + chr(92) + args.username if args.domain else args.username}")
    print(f"  Auth    : {auth_method} ({cred_method})")
    print(f"  Threads : {threads} | Timeout: {timeout}s | Retries: {retries}")
    print()

    interrupted = {"flag": False}

    def signal_handler(sig, frame):
        if interrupted["flag"]:
            sys.exit(1)
        interrupted["flag"] = True
        print(f"\n{C.YELLOW}[!]{C.RESET} Finishing current scans", file=sys.stderr)

    signal.signal(signal.SIGINT, signal_handler)

    all_results: Dict[str, Tuple[Dict, float]] = {}
    start_time = time.time()

    if threads <= 1:
        for target in targets:
            if interrupted["flag"]:
                break
            try:
                all_results[target] = scan_host(target, args.username, args.password,
                                                args.domain, lm, nt, args.aeskey,
                                                args.kerberos, args.kdchost, port,
                                                timeout, retries)
            except KeyboardInterrupt:
                break
            except Exception:
                SecureLogger.error(target, "Scan failed")
                all_results[target] = ({}, 0.0)
    else:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_map = {
                executor.submit(scan_host, t, args.username, args.password,
                              args.domain, lm, nt, args.aeskey, args.kerberos,
                              args.kdchost, port, timeout, retries): t
                for t in targets
            }
            for future in as_completed(future_map):
                target = future_map[future]
                if interrupted["flag"]:
                    future.cancel()
                    continue
                try:
                    all_results[target] = future.result()
                except KeyboardInterrupt:
                    interrupted["flag"] = True
                    break
                except Exception:
                    SecureLogger.error(target, "Scan failed")
                    all_results[target] = ({}, 0.0)

    elapsed = time.time() - start_time

    print(f"\n{C.BOLD}{'═' * 60}{C.RESET}")
    print(f"  {C.BOLD}SUMMARY{C.RESET} — {len(targets)} target(s) in {elapsed:.1f}s")
    print(f"{'═' * 60}{C.RESET}")

    total = 0
    for ip in targets:
        res, cov = all_results.get(ip, ({}, 0.0))
        if res:
            names = ", ".join(sorted(res.keys()))
            high = sum(1 for r in res.values() if r.get("confidence") == "HIGH")
            cov_str = f" [cov {cov:.0%}]" if cov < 0.6 else ""
            total += len(res)
            print(f"  {C.GREEN}{ip}{C.RESET} → {names} [{high} high]{cov_str}")
        else:
            print(f"  {C.CYAN}{ip}{C.RESET} → nothing detected")
    print(f"\n  Total detections: {total}\n")

    if args.json:
        try:
            out_path = Validator.validate_output_path(args.json)
            export_json(all_results, out_path)
        except ValueError as e:
            print(f"{C.RED}[-]{C.RESET} {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
