#!/usr/bin/env python3
"""
AgentBoard Codex session data collector.

PRIVACY: This script ONLY extracts aggregate numeric stats from Codex session
files. It NEVER reads, stores, or transmits conversation content, code,
prompts, or responses.
"""

import glob
import gc
import json
import os
import platform as platform_module
import re
import socket
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import quote

MAX_MINS_PER_DAY = 960
MAX_MINS_PER_SESSION = 480
HUMAN_TOKENS_PER_MIN = 300
SYNC_INTERVAL_SECS = 300
CODEX_IDLE_GAP_SECS = 10 * 60
SESSION_TAIL_SECS = 2 * 60
AGENTBOARD_SCRIPT_RELEASE = "2026-04-30"
__version__ = AGENTBOARD_SCRIPT_RELEASE
CODEX_SYNC_STATE_VERSION = f"{AGENTBOARD_SCRIPT_RELEASE}:codex-replay.1"
ZCODE_SYNC_STATE_VERSION = f"{AGENTBOARD_SCRIPT_RELEASE}:zcode-sqlite.6"
ZCODE_DB_DEFAULT = os.path.expanduser("~/.zcode/cli/db/db.sqlite")
# Only collect ZCode usage from the last N days; older days were already uploaded
# and stay on the server. Keeps scan time, memory and state file bounded.
try:
    ZCODE_MAX_DAYS = max(1, int(os.environ.get("AGENTBOARD_ZCODE_DAYS", "45")))
except ValueError:
    ZCODE_MAX_DAYS = 45
CODEX_REPLAY_GAP_SECS = 10
CODEX_REPLAY_MIN_EVENTS = 100
CODEX_PROVIDER_TOTAL_POLICY_START_DATE = "2026-04-21"
PATCH_FILE_RE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$")
COMMON_CA_BUNDLE_PATHS = (
    "/etc/ssl/cert.pem",
    "/private/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
)


def build_ssl_context():
    candidates = []
    env_bundle = os.environ.get("SSL_CERT_FILE")
    if env_bundle:
        candidates.append(env_bundle)

    try:
        import certifi  # type: ignore

        candidates.append(certifi.where())
    except Exception:
        pass

    try:
        defaults = ssl.get_default_verify_paths()
        candidates.extend([defaults.cafile, defaults.openssl_cafile])
    except Exception:
        pass

    candidates.extend(COMMON_CA_BUNDLE_PATHS)
    seen = set()
    for candidate in candidates:
        if not candidate or candidate in seen or not os.path.exists(candidate):
            continue
        seen.add(candidate)
        try:
            return ssl.create_default_context(cafile=candidate)
        except Exception:
            continue

    return ssl.create_default_context()


def sanitize_host_id(value):
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", (value or "").strip()).strip("._")
    return sanitized[:80] or "unknown"


def detect_device_name():
    env_value = os.environ.get("AGENTBOARD_DEVICE_NAME", "").strip()
    if env_value:
        return env_value
    try:
        hostname = socket.gethostname().strip()
        if hostname:
            return hostname
    except Exception:
        pass
    return ""


def get_host_id():
    return sanitize_host_id(os.environ.get("AGENTBOARD_HOST_ID", "") or detect_device_name())


def normalize_device_platform(value):
    normalized = (value or "").strip().lower()
    if not normalized:
        return ""
    if normalized.startswith("darwin") or normalized in ("mac", "macos", "mac os", "mac os x"):
        return "macos"
    if normalized.startswith("win") or "windows" in normalized:
        return "win32"
    if normalized.startswith("linux") or "linux" in normalized:
        return "linux"
    return normalized


def detect_platform_name():
    env_value = os.environ.get("AGENTBOARD_PLATFORM", "").strip()
    if env_value:
        return normalize_device_platform(env_value)
    try:
        return normalize_device_platform(platform_module.system())
    except Exception:
        return ""


SSL_CONTEXT = build_ssl_context()
AGENTBOARD_DIR = os.path.expanduser("~/.agentboard")
HOST_ID = get_host_id()
LOG_DIR = os.path.join(AGENTBOARD_DIR, "logs")
SYNC_LOG_PATH = os.path.join(LOG_DIR, "codex-sync.log")
LAST_SUCCESS_PATH = os.path.join(LOG_DIR, "last-success.txt")
SYNC_LOCK_PATH = os.path.join(AGENTBOARD_DIR, f"codex-sync.{HOST_ID}.lock")
MAX_LOG_BYTES = 10 * 1024 * 1024


def rotate_log(path):
    try:
        if not os.path.exists(path) or os.path.getsize(path) < MAX_LOG_BYTES:
            return
        backup_one = path + ".1"
        backup_two = path + ".2"
        if os.path.exists(backup_two):
            os.remove(backup_two)
        if os.path.exists(backup_one):
            os.replace(backup_one, backup_two)
        os.replace(path, backup_one)
    except Exception:
        pass


def log_sync(message):
    line = f"[agentboard-codex] {message}"
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        rotate_log(SYNC_LOG_PATH)
        with open(SYNC_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    if sys.stderr.isatty():
        print(line, file=sys.stderr)


def log_sync_error(context, error):
    detail = str(error)
    if isinstance(error, urllib.error.HTTPError):
        try:
            body = error.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        detail = f"HTTP {error.code}: {error.reason}"
        if body:
            detail += f" body={body}"
    log_sync(f"{context}: {detail}")


def mark_last_success():
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LAST_SUCCESS_PATH, "w", encoding="utf-8") as f:
            f.write(datetime.now().astimezone().isoformat() + "\n")
    except Exception:
        pass


def emit_json(payload):
    try:
        print(json.dumps(payload))
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass


def clamp_minutes(active_seconds, max_minutes):
    if active_seconds <= 0:
        return 0
    return min(max_minutes, int(round(active_seconds / 60.0)))


def build_engaged_windows(events, gap_cap_secs, tail_secs):
    if not events:
        return []

    windows = []
    sorted_events = sorted(events, key=lambda e: e[1])
    for index, (_, ts) in enumerate(sorted_events):
        start = ts.timestamp()
        if index + 1 < len(sorted_events):
            next_start = sorted_events[index + 1][1].timestamp()
            end = min(start + gap_cap_secs, next_start)
        else:
            end = start + tail_secs
        if end > start:
            windows.append((start, end))

    if not windows:
        return []

    merged = [list(windows[0])]
    for start, end in windows[1:]:
        last = merged[-1]
        if start <= last[1]:
            last[1] = max(last[1], end)
        else:
            merged.append([start, end])

    return merged


def estimate_engaged_seconds(events, gap_cap_secs, tail_secs):
    windows = build_engaged_windows(events, gap_cap_secs, tail_secs)
    return int(sum(end - start for start, end in windows))


def windows_to_payload(windows):
    return [
        {
            "start_at": datetime.fromtimestamp(start).astimezone().isoformat(),
            "end_at": datetime.fromtimestamp(end).astimezone().isoformat(),
        }
        for start, end in windows
    ]


def build_tool_breakdown(tool_counts, top_n=4):
    total_calls = sum(tool_counts.values())
    if total_calls <= 0:
        return []

    ordered = sorted(
        tool_counts.items(),
        key=lambda item: (-item[1], item[0].lower()),
    )[:top_n]
    return [
        {
            "tool": tool,
            "count": count,
            "percentage": int(round((count / total_calls) * 100)),
        }
        for tool, count in ordered
    ]


def new_day():
    return {
        "events": [],
        "input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
        "provider_total_tokens": 0,
        "cache_read_tokens": 0,
        "cache_creation_tokens": 0,
        "user_msgs": 0,
        "assistant_msgs": 0,
        "lines_added": 0,
        "lines_removed": 0,
        "projects": set(),
        "tool_calls": 0,
        "tool_counts": defaultdict(int),
        "files_touched": set(),
        "tombstone": False,
    }


def normalize_ts(ts_str):
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return None


def safe_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def iter_session_entries(session_file):
    with open(session_file, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = normalize_ts(entry.get("timestamp"))
            if not ts:
                continue

            yield line_number, entry, ts


def load_session_entries(session_file):
    return list(iter_session_entries(session_file))


def token_usage_from_entry(entry):
    if entry.get("type") != "event_msg":
        return None

    payload = entry.get("payload", {})
    if payload.get("type") != "token_count":
        return None

    info = payload.get("info") or {}
    if not isinstance(info, dict):
        info = {}
    total_usage = info.get("total_token_usage") or {}
    if not isinstance(total_usage, dict):
        total_usage = {}

    return (
        safe_int(total_usage.get("input_tokens", 0)),
        safe_int(total_usage.get("output_tokens", 0)),
        safe_int(total_usage.get("cached_input_tokens", 0)),
    )


def detect_replay_prefix(session_file):
    leading_meta_count = 0
    first_entry = None
    for line_number, entry, ts in iter_session_entries(session_file):
        if first_entry is None:
            first_entry = (line_number, entry, ts)
        if entry.get("type") == "session_meta":
            leading_meta_count += 1
            continue
        break

    if leading_meta_count < 2:
        return 1, (0, 0, 0), first_entry

    previous_ts = None
    parsed_count = 0
    baseline_input = 0
    baseline_output = 0
    baseline_cached = 0

    for line_number, entry, ts in iter_session_entries(session_file):
        if (
            previous_ts is not None
            and parsed_count >= CODEX_REPLAY_MIN_EVENTS
            and (ts - previous_ts).total_seconds() >= CODEX_REPLAY_GAP_SECS
        ):
            return line_number, (baseline_input, baseline_output, baseline_cached), first_entry

        usage = token_usage_from_entry(entry)
        if usage:
            total_input, total_output, total_cached = usage
            baseline_input = max(baseline_input, total_input)
            baseline_output = max(baseline_output, total_output)
            baseline_cached = max(baseline_cached, total_cached)

        previous_ts = ts
        parsed_count += 1

    return sys.maxsize, (baseline_input, baseline_output, baseline_cached), first_entry


def iter_session_roots(root_dir):
    normalized_root = os.path.normpath(os.path.abspath(os.path.expanduser(root_dir)))
    roots = [normalized_root]
    archived_root = os.path.join(os.path.dirname(normalized_root), "archived_sessions")
    if (
        os.path.basename(normalized_root) == "sessions"
        and os.path.isdir(archived_root)
    ):
        roots.append(archived_root)

    seen = set()
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        yield root


def iter_session_files(root_dir):
    seen = set()
    for root in iter_session_roots(root_dir):
        pattern = os.path.join(root, "**", "*.jsonl")
        for path in glob.glob(pattern, recursive=True):
            if os.path.isfile(path) and path not in seen:
                seen.add(path)
                yield path


def count_patch_lines(arguments):
    lines_added = 0
    lines_removed = 0
    files_touched = set()

    for line in arguments.splitlines():
        file_match = PATCH_FILE_RE.match(line)
        if file_match:
            files_touched.add(file_match.group(1).strip())
            continue

        if line.startswith("+++ ") or line.startswith("--- "):
            continue
        if line.startswith("+"):
            lines_added += 1
        elif line.startswith("-"):
            lines_removed += 1

    return lines_added, lines_removed, files_touched


def finalize_days(days, max_minutes, include_tombstones=False):
    results = {}
    for date_str, data in days.items():
        events = sorted(data["events"], key=lambda e: e[1])
        if not events:
            if include_tombstones and data.get("tombstone"):
                results[date_str] = {
                    "coding_time_mins": 0,
                    "ai_time_mins": 0,
                    "tokens_used": 0,
                    "provider_total_tokens": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cache_read_tokens": 0,
                    "cache_creation_tokens": 0,
                    "thoughts_tokens": 0,
                    "tool_tokens": 0,
                    "lines_changed": 0,
                    "lines_added": 0,
                    "lines_removed": 0,
                    "messages": 0,
                    "assistant_messages": 0,
                    "projects": len(data["projects"]),
                    "tool_calls": 0,
                    "tool_breakdown": [],
                    "files_touched": 0,
                    "first_event_at": None,
                    "last_event_at": None,
                    "engaged_windows": [],
                }
            continue

        windows = build_engaged_windows(events, CODEX_IDLE_GAP_SECS, SESSION_TAIL_SECS)
        active_seconds = int(sum(end - start for start, end in windows))
        coding_time_mins = clamp_minutes(active_seconds, max_minutes)
        ai_time_mins = (
            max(1, int(data["output_tokens"] / HUMAN_TOKENS_PER_MIN))
            if data["output_tokens"] > 0
            else 0
        )

        results[date_str] = {
            "coding_time_mins": coding_time_mins,
            "ai_time_mins": ai_time_mins,
            "tokens_used": data["input_tokens"] + data["output_tokens"],
            "provider_total_tokens": data["input_tokens"] + data["output_tokens"],
            "input_tokens": data["input_tokens"],
            "output_tokens": data["output_tokens"],
            "cache_read_tokens": data["cache_read_tokens"],
            "cache_creation_tokens": data["cache_creation_tokens"],
            "thoughts_tokens": 0,
            "tool_tokens": 0,
            "lines_changed": data["lines_added"] - data["lines_removed"],
            "lines_added": data["lines_added"],
            "lines_removed": data["lines_removed"],
            "messages": data["user_msgs"] + data["assistant_msgs"],
            "assistant_messages": data["assistant_msgs"],
            "projects": len(data["projects"]),
            "tool_calls": data["tool_calls"],
            "tool_breakdown": build_tool_breakdown(data["tool_counts"]),
            "files_touched": len(data["files_touched"]),
            "first_event_at": events[0][1].isoformat(),
            "last_event_at": events[-1][1].isoformat(),
            "engaged_windows": windows_to_payload(windows),
        }

    return results


def parse_session_events(session_file):
    days = defaultdict(new_day)
    session_id = os.path.splitext(os.path.basename(session_file))[0]
    if session_id.endswith(".jsonl"):
        session_id = session_id[:-6]

    session_cwd = ""
    saw_session_meta = False
    skip_before_line, token_baseline, first_entry_info = detect_replay_prefix(session_file)
    prev_input_tokens, prev_output_tokens, prev_cached_input_tokens = token_baseline

    if skip_before_line == sys.maxsize and first_entry_info:
        _, first_entry, first_ts = first_entry_info
        date_key = first_ts.astimezone().strftime("%Y-%m-%d")
        day = days[date_key]
        day["tombstone"] = True
        payload = first_entry.get("payload", {})
        if first_entry.get("type") == "session_meta":
            session_id = payload.get("id") or session_id
            session_cwd = payload.get("cwd") or session_cwd
        if session_cwd:
            day["projects"].add(session_cwd)

    for line_number, entry, ts in iter_session_entries(session_file):
            if line_number < skip_before_line:
                payload = entry.get("payload", {})
                if entry.get("type") == "session_meta":
                    if not saw_session_meta:
                        session_id = payload.get("id") or session_id
                        saw_session_meta = True
                    session_cwd = payload.get("cwd") or session_cwd
                elif not session_cwd:
                    session_cwd = payload.get("cwd") or entry.get("cwd") or session_cwd
                continue

            date_key = ts.astimezone().strftime("%Y-%m-%d")
            day = days[date_key]

            if not session_cwd:
                payload = entry.get("payload", {})
                session_cwd = (
                    payload.get("cwd")
                    or entry.get("cwd")
                    or session_cwd
                )
                if session_cwd:
                    day["projects"].add(session_cwd)

            entry_type = entry.get("type")
            payload = entry.get("payload", {})

            if entry_type == "session_meta":
                if not saw_session_meta:
                    session_id = payload.get("id") or session_id
                    saw_session_meta = True
                if payload.get("cwd"):
                    session_cwd = payload["cwd"]
                    day["projects"].add(session_cwd)
                continue

            if entry_type == "turn_context":
                if payload.get("cwd"):
                    session_cwd = payload["cwd"]
                    day["projects"].add(session_cwd)
                continue

            if entry_type == "event_msg":
                payload_type = payload.get("type")
                if payload_type == "user_message":
                    day["events"].append(("user_message", ts))
                    day["user_msgs"] += 1
                    if session_cwd:
                        day["projects"].add(session_cwd)
                elif payload_type == "agent_message":
                    day["events"].append(("assistant_message", ts))
                    day["assistant_msgs"] += 1
                elif payload_type == "token_count":
                    usage = token_usage_from_entry(entry) or (0, 0, 0)
                    total_input, total_output, total_cached = usage
                    delta_input = max(0, total_input - prev_input_tokens)
                    delta_output = max(0, total_output - prev_output_tokens)
                    delta_cached = max(0, total_cached - prev_cached_input_tokens)
                    prev_input_tokens = max(prev_input_tokens, total_input)
                    prev_output_tokens = max(prev_output_tokens, total_output)
                    prev_cached_input_tokens = max(prev_cached_input_tokens, total_cached)
                    day["input_tokens"] += delta_input
                    day["output_tokens"] += delta_output
                    day["cache_read_tokens"] += delta_cached
                    day["events"].append(("token_count", ts))
                continue

            if entry_type != "response_item":
                continue

            payload_type = payload.get("type", "")

            # custom_tool_call: apply_patch lives here in Codex
            if payload_type == "custom_tool_call":
                day["events"].append(("tool_call", ts))
                day["tool_calls"] += 1
                name = payload.get("name", "")
                if name:
                    day["tool_counts"][name] += 1
                if name == "apply_patch":
                    patch_text = payload.get("input") or ""
                    lines_added, lines_removed, files_touched = count_patch_lines(patch_text)
                    day["lines_added"] += lines_added
                    day["lines_removed"] += lines_removed
                    day["files_touched"].update(files_touched)
                continue

            if payload_type != "function_call":
                continue

            day["events"].append(("tool_call", ts))
            day["tool_calls"] += 1

            name = payload.get("name", "")
            if name:
                day["tool_counts"][name] += 1
            arguments = payload.get("arguments") or ""

            if name == "apply_patch":
                lines_added, lines_removed, files_touched = count_patch_lines(arguments)
                day["lines_added"] += lines_added
                day["lines_removed"] += lines_removed
                day["files_touched"].update(files_touched)
                continue

            try:
                parsed_args = json.loads(arguments)
            except (TypeError, ValueError, json.JSONDecodeError):
                parsed_args = {}

            workdir = parsed_args.get("workdir", "")
            if workdir:
                day["projects"].add(workdir)

    return session_id, days


def parse_session(session_file):
    session_id, days = parse_session_events(session_file)
    return session_id, finalize_days(
        days,
        MAX_MINS_PER_SESSION,
        include_tombstones=True,
    )


def zcode_db_path():
    return os.path.expanduser(os.environ.get("AGENTBOARD_ZCODE_DB", ZCODE_DB_DEFAULT))


def zcode_db_signature(db_path):
    try:
        connection = zcode_db_connect(db_path)
        row = connection.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM session), "
            "COALESCE((SELECT MAX(time_updated) FROM session), 0), "
            "(SELECT COUNT(*) FROM model_usage), "
            "COALESCE((SELECT MAX(started_at) FROM model_usage), 0), "
            "COALESCE((SELECT MAX(completed_at) FROM model_usage), 0), "
            "COALESCE((SELECT SUM(input_tokens + output_tokens + reasoning_tokens + cache_creation_input_tokens + cache_read_input_tokens + computed_total_tokens) FROM model_usage), 0), "
            "(SELECT COUNT(*) FROM message), "
            "COALESCE((SELECT MAX(time_updated) FROM message), 0), "
            "(SELECT COUNT(*) FROM tool_usage), "
            "COALESCE((SELECT MAX(completed_at) FROM tool_usage), 0)"
        ).fetchone()
        connection.close()
    except (OSError, sqlite3.Error):
        return "unavailable"
    return ":".join(str(safe_int(value)) for value in row)


def zcode_db_connect(db_path):
    uri = f"file:{quote(os.path.abspath(db_path), safe='/')}?mode=ro"
    return sqlite3.connect(uri, uri=True, timeout=1.0)


def zcode_datetime(epoch_ms):
    try:
        return datetime.fromtimestamp(safe_int(epoch_ms) / 1000.0).astimezone()
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def zcode_day_state():
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
        "cache_read_tokens": 0,
        "cache_creation_tokens": 0,
        "provider_total_tokens": 0,
        "user_msgs": 0,
        "assistant_msgs": 0,
        "tool_calls": 0,
        "tool_counts": defaultdict(int),
        "projects": set(),
        "files_touched": set(),
        "lines_added": 0,
        "lines_removed": 0,
        # Merged activity runs [[start, end]] in epoch seconds; one entry per
        # gap-bridged stretch instead of one entry per event, so per-day memory
        # stays bounded no matter how many events accumulate.
        "runs": [],
    }


def zcode_add_point(day, epoch_ms):
    if not epoch_ms:
        return
    ts = safe_int(epoch_ms) / 1000.0
    runs = day["runs"]
    low, high = 0, len(runs)
    while low < high:
        mid = (low + high) // 2
        if runs[mid][0] <= ts:
            low = mid + 1
        else:
            high = mid
    index = low
    touches_previous = index > 0 and ts - runs[index - 1][1] <= CODEX_IDLE_GAP_SECS
    touches_next = index < len(runs) and runs[index][0] - ts <= CODEX_IDLE_GAP_SECS
    if touches_previous and touches_next:
        runs[index - 1][1] = runs[index][1]
        del runs[index]
    elif touches_previous:
        if ts > runs[index - 1][1]:
            runs[index - 1][1] = ts
    elif touches_next:
        runs[index][0] = ts
    else:
        runs.insert(index, [ts, ts])


def zcode_add_request(day, request, session_directory):
    total_input = safe_int(request.get("input_tokens"))
    cache_read = safe_int(request.get("cache_read_input_tokens"))
    cache_creation = safe_int(request.get("cache_creation_input_tokens"))
    # ZCode input_tokens already includes cached tokens (totalTokens = input + output).
    # AgentBoard displays tokens_used + cache_read + cache_creation, so upload the
    # non-cache portion as input to avoid double counting the cache.
    day["provider_total_tokens"] += safe_int(request.get("computed_total_tokens"))
    day["input_tokens"] += max(0, total_input - cache_read - cache_creation)
    day["output_tokens"] += safe_int(request.get("output_tokens"))
    day["reasoning_tokens"] += safe_int(request.get("reasoning_tokens"))
    day["cache_read_tokens"] += cache_read
    day["cache_creation_tokens"] += cache_creation
    if session_directory:
        day["projects"].add(session_directory)
    zcode_add_point(day, request.get("started_at"))
    zcode_add_point(day, request.get("completed_at"))


def zcode_merge_runs(runs):
    ordered = sorted(runs)
    merged = []
    for start, end in ordered:
        if merged and start - merged[-1][1] <= CODEX_IDLE_GAP_SECS:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def zcode_build_windows(runs):
    # Gap-bridged active windows over merged activity runs; must match
    # build_engaged_windows exactly: a run ends at last event + gap cap, except
    # the day's final run which ends at last event + session tail. Runs from
    # different sessions on the same day may need re-merging, so normalize first.
    merged = zcode_merge_runs(runs)
    if not merged:
        return []
    windows = []
    for run in merged[:-1]:
        windows.append((run[0], run[1] + CODEX_IDLE_GAP_SECS))
    windows.append((merged[-1][0], merged[-1][1] + SESSION_TAIL_SECS))
    return windows


def zcode_finalize_day(data, max_minutes):
    runs = zcode_merge_runs(data.get("runs", []))
    windows = zcode_build_windows(runs)
    if not windows:
        return None
    first_event = zcode_datetime(runs[0][0] * 1000)
    last_event = zcode_datetime(runs[-1][1] * 1000)
    active_seconds = int(sum(end - start for start, end in windows))
    output_tokens = safe_int(data.get("output_tokens"))
    return {
        "coding_time_mins": clamp_minutes(active_seconds, max_minutes),
        "ai_time_mins": max(1, int(output_tokens / HUMAN_TOKENS_PER_MIN)) if output_tokens else 0,
        "tokens_used": safe_int(data.get("input_tokens")) + output_tokens,
        "provider_total_tokens": safe_int(data.get("provider_total_tokens")),
        "input_tokens": safe_int(data.get("input_tokens")),
        "output_tokens": output_tokens,
        "cache_read_tokens": safe_int(data.get("cache_read_tokens")),
        "cache_creation_tokens": safe_int(data.get("cache_creation_tokens")),
        "thoughts_tokens": safe_int(data.get("reasoning_tokens")),
        "tool_tokens": 0,
        "lines_changed": safe_int(data.get("lines_added")) - safe_int(data.get("lines_removed")),
        "lines_added": safe_int(data.get("lines_added")),
        "lines_removed": safe_int(data.get("lines_removed")),
        "messages": safe_int(data.get("user_msgs")) + safe_int(data.get("assistant_msgs")),
        "assistant_messages": safe_int(data.get("assistant_msgs")),
        "projects": len(data.get("projects", set())),
        "tool_calls": safe_int(data.get("tool_calls")),
        "tool_breakdown": build_tool_breakdown(data.get("tool_counts", {})),
        "files_touched": len(data.get("files_touched", set())),
        "first_event_at": first_event.isoformat() if first_event else None,
        "last_event_at": last_event.isoformat() if last_event else None,
        "engaged_windows": windows_to_payload(windows),
    }


def zcode_collect_sessions(verbose=False):
    db_path = zcode_db_path()
    if not os.path.isfile(db_path):
        return [], {}, {"status": "no_zcode_db", "db_path": db_path, "scanned": 0}

    session_days = defaultdict(lambda: defaultdict(zcode_day_state))
    sessions_with_requests = set()
    scanned = 0
    request_count = 0
    message_count = 0
    tool_count = 0

    def day_for(session_id, epoch_ms):
        stamp = zcode_datetime(epoch_ms)
        if not stamp:
            return None
        return session_days[session_id][stamp.strftime("%Y-%m-%d")]

    # Sliding window: rows older than the cutoff were uploaded long ago and are
    # immutable history, so skip them entirely to keep scans bounded.
    cutoff_ms = int((datetime.now().astimezone() - timedelta(days=ZCODE_MAX_DAYS - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    ).timestamp() * 1000)

    try:
        connection = zcode_db_connect(db_path)
        session_dirs = {}
        for session_id, directory in connection.execute("SELECT id, directory FROM session"):
            session_dirs[session_id] = directory or ""
            scanned += 1

        # Stream model_usage instead of fetchall so only aggregate state stays in memory.
        # Tokens come from completed requests; error/cancelled requests still count as
        # activity (their start/end feed the engaged windows) but contribute no tokens.
        seen_request_ids = set()
        request_cursor = connection.execute(
            "SELECT session_id, logical_request_id, status, started_at, completed_at, "
            "input_tokens, output_tokens, reasoning_tokens, cache_creation_input_tokens, "
            "cache_read_input_tokens, computed_total_tokens "
            "FROM model_usage WHERE started_at >= ? ORDER BY session_id, started_at, logical_request_id",
            (cutoff_ms,),
        )
        for session_id, request_key, status, started_ms, completed_ms, total_input, output_tokens, reasoning_tokens, cache_creation, cache_read, computed_total in request_cursor:
            request_count += 1
            if request_key:
                if request_key in seen_request_ids:
                    continue
                seen_request_ids.add(request_key)
            sessions_with_requests.add(session_id)
            day = day_for(session_id, started_ms)
            if not day:
                continue
            request = {
                "started_at": started_ms,
                "completed_at": completed_ms,
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "computed_total_tokens": 0,
            }
            if status == "completed":
                request.update({
                    "input_tokens": total_input,
                    "output_tokens": output_tokens,
                    "reasoning_tokens": reasoning_tokens,
                    "cache_creation_input_tokens": cache_creation,
                    "cache_read_input_tokens": cache_read,
                    "computed_total_tokens": computed_total,
                })
            zcode_add_request(day, request, session_dirs.get(session_id, ""))

        # Extract only the role field in SQL so full message bodies never enter Python memory.
        try:
            connection.execute("SELECT json_extract('{}', '$.a')")
            message_cursor = connection.execute(
                "SELECT session_id, time_created, json_extract(data, '$.role') FROM message "
                "WHERE time_created >= ? ORDER BY time_created",
                (cutoff_ms,),
            )
            for session_id, epoch_ms, role in message_cursor:
                message_count += 1
                if session_id not in sessions_with_requests:
                    continue
                day = day_for(session_id, epoch_ms)
                if not day:
                    continue
                if role == "user":
                    day["user_msgs"] += 1
                elif role == "assistant":
                    day["assistant_msgs"] += 1
                zcode_add_point(day, epoch_ms)
        except sqlite3.OperationalError:
            for session_id, epoch_ms, raw_data in connection.execute(
                "SELECT session_id, time_created, data FROM message WHERE time_created >= ? ORDER BY time_created",
                (cutoff_ms,),
            ):
                message_count += 1
                if session_id not in sessions_with_requests:
                    continue
                day = day_for(session_id, epoch_ms)
                if not day:
                    continue
                try:
                    role = (json.loads(raw_data) or {}).get("role", "")
                except (TypeError, ValueError, json.JSONDecodeError):
                    role = ""
                if role == "user":
                    day["user_msgs"] += 1
                elif role == "assistant":
                    day["assistant_msgs"] += 1
                zcode_add_point(day, epoch_ms)

        for session_id, epoch_ms, tool_name in connection.execute(
            "SELECT session_id, started_at, tool_name FROM tool_usage WHERE started_at >= ? ORDER BY started_at",
            (cutoff_ms,),
        ):
            tool_count += 1
            if session_id not in sessions_with_requests:
                continue
            day = day_for(session_id, epoch_ms)
            if not day:
                continue
            day["tool_calls"] += 1
            if tool_name:
                day["tool_counts"][str(tool_name)] += 1
            zcode_add_point(day, epoch_ms)

        connection.close()
    except (OSError, sqlite3.Error) as error:
        if verbose:
            log_sync(f"failed to read ZCode database {db_path}: {error}")
        return [], {}, {"status": "zcode_db_error", "db_path": db_path, "scanned": 0, "error": str(error)}

    all_sessions = []
    merged_days = defaultdict(zcode_day_state)
    for session_id, days in session_days.items():
        for date_str, data in sorted(days.items()):
            stats = zcode_finalize_day(data, MAX_MINS_PER_SESSION)
            if not stats:
                continue
            entry = {
                "date": date_str,
                "session_id": f"opencode:zcode:{session_id}",
                **stats,
            }
            all_sessions.append(entry)
            merged = merged_days[date_str]
            for key in ("input_tokens", "output_tokens", "reasoning_tokens", "cache_read_tokens", "cache_creation_tokens", "provider_total_tokens", "user_msgs", "assistant_msgs", "tool_calls", "lines_added", "lines_removed"):
                merged[key] += data.get(key, 0)
            merged["runs"].extend(data["runs"])
            merged["projects"].update(data["projects"])
            for tool_name, count in data["tool_counts"].items():
                merged["tool_counts"][tool_name] += count
            merged["files_touched"].update(data["files_touched"])

    daily = {}
    for date_str, data in merged_days.items():
        stats = zcode_finalize_day(data, MAX_MINS_PER_DAY)
        if stats:
            daily[date_str] = stats
    return all_sessions, daily, {
        "status": "ok",
        "db_path": db_path,
        "scanned": scanned,
        "requests": request_count,
        "messages": message_count,
        "tools": tool_count,
    }


def zcode_summary_mode(verbose=False):
    sessions, daily, meta = zcode_collect_sessions(verbose=verbose)
    totals = {
        "total_coding_mins": sum(row["coding_time_mins"] for row in daily.values()),
        "total_ai_mins": sum(row["ai_time_mins"] for row in daily.values()),
        "total_tokens": sum(row["tokens_used"] for row in daily.values()),
        "total_input_tokens": sum(row["input_tokens"] for row in daily.values()),
        "total_output_tokens": sum(row["output_tokens"] for row in daily.values()),
        "total_lines_changed": sum(row["lines_changed"] for row in daily.values()),
        "total_lines_added": sum(row["lines_added"] for row in daily.values()),
        "total_lines_removed": sum(row["lines_removed"] for row in daily.values()),
        "total_sessions": len(sessions),
        "total_messages": sum(row["messages"] for row in daily.values()),
        "total_assistant_messages": sum(row["assistant_messages"] for row in daily.values()),
        "total_tool_calls": sum(row["tool_calls"] for row in daily.values()),
        "total_files_touched": sum(row["files_touched"] for row in daily.values()),
        "total_days": len(daily),
    }
    return {"summary": totals, "sessions": sessions, "daily": daily, "meta": meta}


def summary_mode(session_dir, verbose=False):
    codex_summary = None
    codex_sessions = []
    codex_daily = {}
    if resolve_session_dir(session_dir, load_config() or {}):
        # Reuse the original Codex summary implementation without duplicating its parser.
        codex_sessions, codex_daily = _codex_summary_data(session_dir, verbose=verbose)
    zcode = zcode_summary_mode(verbose=verbose)
    sessions = codex_sessions + zcode["sessions"]
    daily = defaultdict(new_day)
    for source_daily in (codex_daily, zcode["daily"]):
        for date_str, stats in source_daily.items():
            daily[date_str]["events"].extend(
                ("summary", normalize_ts(stats["first_event_at"]))
                for _ in ([0] if stats.get("first_event_at") else [])
            )
            for key in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens", "lines_added", "lines_removed", "user_msgs", "assistant_msgs", "tool_calls"):
                daily[date_str][key] += stats.get(key, 0)
    # Preserve the established Codex daily output and expose ZCode alongside it.
    totals = {
        "total_coding_mins": sum(row.get("coding_time_mins", 0) for row in codex_daily.values()) + zcode["summary"]["total_coding_mins"],
        "total_ai_mins": sum(row.get("ai_time_mins", 0) for row in codex_daily.values()) + zcode["summary"]["total_ai_mins"],
        "total_tokens": sum(row.get("tokens_used", 0) for row in codex_daily.values()) + zcode["summary"]["total_tokens"],
        "total_input_tokens": sum(row.get("input_tokens", 0) for row in codex_daily.values()) + zcode["summary"]["total_input_tokens"],
        "total_output_tokens": sum(row.get("output_tokens", 0) for row in codex_daily.values()) + zcode["summary"]["total_output_tokens"],
        "total_lines_changed": sum(row.get("lines_changed", 0) for row in codex_daily.values()) + zcode["summary"]["total_lines_changed"],
        "total_lines_added": sum(row.get("lines_added", 0) for row in codex_daily.values()) + zcode["summary"]["total_lines_added"],
        "total_lines_removed": sum(row.get("lines_removed", 0) for row in codex_daily.values()) + zcode["summary"]["total_lines_removed"],
        "total_sessions": len(sessions),
        "total_messages": sum(row.get("messages", 0) for row in codex_daily.values()) + zcode["summary"]["total_messages"],
        "total_assistant_messages": sum(row.get("assistant_messages", 0) for row in codex_daily.values()) + zcode["summary"]["total_assistant_messages"],
        "total_tool_calls": sum(row.get("tool_calls", 0) for row in codex_daily.values()) + zcode["summary"]["total_tool_calls"],
        "total_files_touched": sum(row.get("files_touched", 0) for row in codex_daily.values()) + zcode["summary"]["total_files_touched"],
        "total_days": len(set(codex_daily) | set(zcode["daily"])),
    }
    if verbose:
        log_sync(f"summary complete: codex_sessions={len(codex_sessions)} zcode_sessions={len(zcode['sessions'])} days={totals['total_days']}")
    emit_json({"summary": totals, "sessions": sessions, "daily": {**codex_daily, **{f"zcode:{date}": stats for date, stats in zcode["daily"].items()}}})


def _codex_summary_data(session_dir, verbose=False):
    all_sessions = []
    merged_days = defaultdict(new_day)
    scanned = 0
    config = load_config() or {}
    resolved_session_dir = resolve_session_dir(session_dir, config)
    if not resolved_session_dir:
        return [], {},
    for session_file in iter_session_files(resolved_session_dir):
        scanned += 1
        try:
            session_id, day_data = parse_session_events(session_file)
        except Exception as error:
            if verbose:
                log_sync(f"failed to parse {session_file}: {error}")
            continue
        for date_str, data in day_data.items():
            stats = finalize_days({date_str: data}, MAX_MINS_PER_SESSION).get(date_str)
            if not stats:
                continue
            all_sessions.append({"date": date_str, "session_id": f"codex:{session_id}", **stats})
            merged = merged_days[date_str]
            merged["events"].extend(data["events"])
            for key in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens", "user_msgs", "assistant_msgs", "lines_added", "lines_removed", "tool_calls"):
                merged[key] += data[key]
            merged["projects"].update(data["projects"])
            merged["tool_counts"].update(data["tool_counts"])
            merged["files_touched"].update(data["files_touched"])
    return all_sessions, finalize_days(merged_days, MAX_MINS_PER_DAY)


def policy_era_for_date(date_str):
    if not date_str:
        return "codex_provider_current"
    if date_str < CODEX_PROVIDER_TOTAL_POLICY_START_DATE:
        return "codex_provider_legacy_pre_2026_04_21"
    return "codex_provider_current_input_plus_output"


def iter_dates(start_date, end_date):
    start = datetime.strptime(start_date, "%Y-%m-%d").date()
    end = datetime.strptime(end_date, "%Y-%m-%d").date()
    if end < start:
        start, end = end, start
    current = start
    while current <= end:
        yield current.isoformat()
        current += timedelta(days=1)


def build_diagnose_payload(session_dir, dates):
    target_dates = set(dates)
    scanned = 0
    matched_sessions = 0
    by_date = {
        date_str: {
            "date": date_str,
            "policy_era": policy_era_for_date(date_str),
            "sessions": 0,
            "provider_total_tokens": 0,
            "tokens_used": 0,
            "legacy_tokens_plus_cache": 0,
            "double_count_if_cache_added": 0,
            "non_cache_total": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "cache_creation_tokens": 0,
            "negative_non_cache": False,
        }
        for date_str in sorted(target_dates)
    }

    for session_file in iter_session_files(session_dir):
        scanned += 1
        try:
            session_id, day_stats = parse_session(session_file)
        except Exception as error:
            continue

        for date_str, stats in day_stats.items():
            if date_str not in target_dates:
                continue
            matched_sessions += 1
            row = by_date[date_str]
            provider_total = stats.get("provider_total_tokens", 0) or 0
            cache_total = (
                (stats.get("cache_read_tokens", 0) or 0)
                + (stats.get("cache_creation_tokens", 0) or 0)
            )
            non_cache = provider_total - cache_total
            row["sessions"] += 1
            row["provider_total_tokens"] += provider_total
            row["tokens_used"] += stats.get("tokens_used", 0) or 0
            row["legacy_tokens_plus_cache"] += (stats.get("tokens_used", 0) or 0) + cache_total
            row["double_count_if_cache_added"] += provider_total + cache_total
            row["non_cache_total"] += non_cache
            row["input_tokens"] += stats.get("input_tokens", 0) or 0
            row["output_tokens"] += stats.get("output_tokens", 0) or 0
            row["cache_read_tokens"] += stats.get("cache_read_tokens", 0) or 0
            row["cache_creation_tokens"] += stats.get("cache_creation_tokens", 0) or 0
            if non_cache < 0:
                row["negative_non_cache"] = True

    return {
        "source": "codex",
        "collector_version": __version__,
        "session_dir": session_dir,
        "scan_roots": list(iter_session_roots(session_dir)),
        "env": {
            "CODEX_HOME": os.environ.get("CODEX_HOME", ""),
            "HOME": os.path.expanduser("~"),
        },
        "files_scanned": scanned,
        "matched_sessions": matched_sessions,
        "dates": [by_date[date_str] for date_str in sorted(by_date)],
    }


def diagnose_mode(session_dir, dates):
    emit_json(build_diagnose_payload(session_dir, dates))


def load_config():
    config_path = os.path.join(AGENTBOARD_DIR, "config.json")
    try:
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
    except Exception:
        return None

    api = config.get("api", "")
    if not api:
        return None

    token = config.get("token", "")
    if not token:
        config = recover_token_from_claim(config_path, config)
        token = config.get("token", "")
    if not token:
        return None

    return {
        "token": token,
        "api": api,
        "device_name": config.get("device_name") or detect_device_name(),
        "platform": config.get("platform") or detect_platform_name(),
        "codex_sessions_path": config.get("codex_sessions_path", ""),
        "logs_dir": config.get("logs_dir", LOG_DIR),
    }


def resolve_session_dir(cli_value, config):
    candidates = []
    if cli_value:
        candidates.append(cli_value)
    if config.get("codex_sessions_path"):
        candidates.append(config["codex_sessions_path"])

    home = os.path.expanduser("~")
    codex_home = os.environ.get("CODEX_HOME", "")
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    candidates.extend(
        [
            os.path.join(codex_home, "sessions") if codex_home else "",
            os.path.join(home, ".codex", "sessions"),
            os.path.join(appdata, "codex", "sessions") if appdata else "",
            os.path.join(localappdata, "codex", "sessions") if localappdata else "",
        ]
    )

    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        normalized = os.path.abspath(os.path.expanduser(candidate))
        if normalized in seen:
            continue
        seen.add(normalized)
        if os.path.isdir(normalized):
            return normalized

    return ""


def recover_token_from_claim(config_path, config):
    claim_code = config.get("claim_code", "")
    api = config.get("api", "")
    if not claim_code or not api:
        return config

    api_base = api.replace("/api/checkin", "")
    try:
        req = urllib.request.Request(
            f"{api_base}/api/claim/{claim_code}/status",
            headers={"User-Agent": "AgentBoard-CLI/1.0"},
        )
        response = urllib.request.urlopen(req, timeout=5, context=SSL_CONTEXT)
        data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return config

    token = data.get("token", "") if data.get("status") == "claimed" else ""
    if not token:
        return config

    config["token"] = token
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except Exception:
        pass
    return config


def post_session(config, session_entry, full_rescan=False, source="codex"):
    payload = json.dumps(
        {
            "token": config["token"],
            "source": source,
            "device_name": config.get("device_name", ""),
            "platform": config.get("platform", ""),
            "full_rescan": full_rescan,
            "session_id": session_entry["session_id"],
            "date": session_entry["date"],
            "coding_time_mins": session_entry["coding_time_mins"],
            "ai_time_mins": session_entry["ai_time_mins"],
            "tokens_used": session_entry["tokens_used"],
            "provider_total_tokens": session_entry.get("provider_total_tokens", 0),
            "input_tokens": session_entry["input_tokens"],
            "output_tokens": session_entry["output_tokens"],
            "cache_read_tokens": session_entry.get("cache_read_tokens", 0),
            "cache_creation_tokens": session_entry.get("cache_creation_tokens", 0),
            "thoughts_tokens": session_entry.get("thoughts_tokens", 0),
            "tool_tokens": session_entry.get("tool_tokens", 0),
            "lines_changed": session_entry["lines_changed"],
            "lines_added": session_entry["lines_added"],
            "lines_removed": session_entry["lines_removed"],
            "sessions": 1,
            "messages": session_entry["messages"],
            "assistant_messages": session_entry["assistant_messages"],
            "projects": session_entry["projects"],
            "tool_calls": session_entry["tool_calls"],
            "tool_breakdown": session_entry.get("tool_breakdown", []),
            "files_touched": session_entry["files_touched"],
            "first_event_at": session_entry["first_event_at"],
            "last_event_at": session_entry["last_event_at"],
            "engaged_windows": session_entry["engaged_windows"],
            "collector_version": __version__,
        }
    )

    req = urllib.request.Request(
        config["api"],
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "AgentBoard-CLI/1.0"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10, context=SSL_CONTEXT)
    except urllib.error.HTTPError as error:
        body = ""
        try:
            body = error.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        message = f"HTTP {error.code}: {error.reason}"
        if body:
            message += f" body={body}"
        raise RuntimeError(message) from error


def load_sync_state():
    state_path = os.path.join(AGENTBOARD_DIR, f"codex-sync-state.{HOST_ID}.json")
    try:
        with open(state_path, encoding="utf-8") as f:
            raw_state = json.load(f)
    except Exception:
        return state_path, {}, False

    if not isinstance(raw_state, dict):
        return state_path, {}, False

    if raw_state.get("_collector_version") != CODEX_SYNC_STATE_VERSION:
        return state_path, {}, True

    files = raw_state.get("files")
    if isinstance(files, dict):
        return state_path, files, False
    return state_path, raw_state, False


def save_sync_state(state_path, state):
    state_dir = os.path.dirname(state_path)
    if state_dir:
        os.makedirs(state_dir, exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(
            {"_collector_version": CODEX_SYNC_STATE_VERSION, "files": state},
            f,
            indent=2,
            sort_keys=True,
        )


def acquire_sync_lock():
    try:
        import fcntl
    except Exception:
        return None

    os.makedirs(AGENTBOARD_DIR, exist_ok=True)
    lock_file = open(SYNC_LOCK_PATH, "w", encoding="utf-8")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock_file.close()
        return False
    return lock_file


def file_signature(path):
    stat_result = os.stat(path)
    return f"{stat_result.st_mtime_ns}:{stat_result.st_size}"


def load_zcode_sync_state():
    state_path = os.path.join(AGENTBOARD_DIR, f"zcode-sync-state.{HOST_ID}.json")
    try:
        with open(state_path, encoding="utf-8") as f:
            raw_state = json.load(f)
    except Exception:
        return state_path, {}, True, ""
    if not isinstance(raw_state, dict) or raw_state.get("_collector_version") != ZCODE_SYNC_STATE_VERSION:
        return state_path, {}, True, ""
    entries = raw_state.get("entries")
    if not isinstance(entries, dict):
        entries = {}
    return state_path, entries, False, str(raw_state.get("_db_signature") or "")


def save_zcode_sync_state(state_path, entries, db_signature):
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "_collector_version": ZCODE_SYNC_STATE_VERSION,
                "_db_signature": db_signature,
                "entries": entries,
            },
            f,
            indent=2,
            sort_keys=True,
        )


def zcode_entry_signature(entry):
    import hashlib

    stable = {k: entry.get(k) for k in sorted(entry) if k not in ("date", "first_event_at", "last_event_at")}
    payload = json.dumps({"date": entry.get("date"), "stats": stable}, sort_keys=True, default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def sync_zcode(config, verbose=False):
    db_path = zcode_db_path()
    state_path, known_entries, state_invalidated, known_signature = load_zcode_sync_state()

    signature = zcode_db_signature(db_path)
    if signature == "unavailable":
        log_sync_error("failed to read ZCode database signature", RuntimeError(signature))
        return {"scanned": 0, "skipped": 0, "synced": 0, "errors": 1, "state": state_path}

    # Fast path: the signature aggregates row counts/timestamps/token sums for the
    # whole database, so equality means nothing to collect or upload changed.
    if not state_invalidated and known_signature and known_signature == signature:
        return {"scanned": 0, "skipped": 0, "synced": 0, "errors": 0, "state": state_path, "unchanged": True}

    sessions, _, meta = zcode_collect_sessions(verbose=verbose)
    if meta.get("status") != "ok":
        return {"scanned": meta.get("scanned", 0), "skipped": 0, "synced": 0, "errors": 1, "state": state_path}

    pending = []
    next_entries = {}
    for entry in sessions:
        key = f"{entry['session_id']}|{entry['date']}"
        entry_signature = zcode_entry_signature(entry)
        next_entries[key] = entry_signature
        if state_invalidated or known_entries.get(key) != entry_signature:
            pending.append(entry)

    if not pending:
        if next_entries != known_entries or known_signature != signature:
            try:
                save_zcode_sync_state(state_path, next_entries, signature)
            except Exception:
                pass
        return {"scanned": meta.get("scanned", 0), "skipped": len(sessions), "synced": 0, "errors": 0, "state": state_path}

    synced = 0
    try:
        for entry in pending:
            if verbose:
                log_sync(
                    "posting zcode "
                    f"session={entry['session_id']} date={entry['date']} "
                    f"tokens={entry.get('tokens_used', 0)}"
                )
            post_session(config, entry, full_rescan=state_invalidated, source="opencode")
            synced += 1
        save_zcode_sync_state(state_path, next_entries, signature)
    except Exception as error:
        log_sync_error("failed to sync ZCode database", error)
        return {"scanned": meta.get("scanned", 0), "skipped": 0, "synced": synced, "errors": 1, "state": state_path}
    return {"scanned": meta.get("scanned", 0), "skipped": len(sessions) - synced, "synced": synced, "errors": 0, "state": state_path}


def sync_mode(session_dir, verbose=False):
    config = load_config()
    if not config:
        if verbose:
            log_sync("missing config/token/api; aborting sync")
        return {
            "status": "config_error",
            "message": "Missing config/token/api",
            "session_dir": "",
            "scanned": 0,
            "skipped": 0,
            "synced": 0,
            "errors": 1,
        }

    resolved_session_dir = resolve_session_dir(session_dir, config)
    sync_lock = acquire_sync_lock()
    if sync_lock is False:
        if verbose:
            log_sync("another Codex sync is already running; skipping")
        return {
            "status": "skipped",
            "message": "Another Codex sync is already running",
            "session_dir": resolved_session_dir or "",
            "scanned": 0,
            "skipped": 0,
            "synced": 0,
            "errors": 0,
        }

    state_path, state, state_invalidated = load_sync_state()
    full_rescan_mode = bool(state_invalidated)
    next_state = {}
    scanned = skipped = synced = errors = 0

    if resolved_session_dir:
        for session_file in iter_session_files(resolved_session_dir):
            scanned += 1
            try:
                signature = file_signature(session_file)
            except OSError as error:
                if verbose:
                    log_sync(f"failed to stat {session_file}: {error}")
                errors += 1
                continue
            if not state_invalidated and state.get(session_file) == signature:
                next_state[session_file] = signature
                skipped += 1
                continue
            try:
                session_id, day_stats = parse_session(session_file)
                for date_str, stats in day_stats.items():
                    if verbose:
                        log_sync(
                            "posting "
                            f"{session_file} date={date_str} coding={stats.get('coding_time_mins', 0)} "
                            f"messages={stats.get('messages', 0)} tool_calls={stats.get('tool_calls', 0)} "
                            f"files_touched={stats.get('files_touched', 0)} tokens={stats.get('tokens_used', 0)}"
                        )
                    post_session(config, {"session_id": f"codex:{session_id}", "date": date_str, **stats}, full_rescan=full_rescan_mode)
                    synced += 1
                next_state[session_file] = signature
            except Exception as error:
                log_sync_error(f"failed to sync {session_file}", error)
                errors += 1
            finally:
                gc.collect()
    elif verbose:
        log_sync("no Codex sessions directory; continuing with ZCode")

    try:
        save_sync_state(state_path, next_state)
    except Exception as error:
        log_sync_error(f"failed to save sync state {state_path}", error)
        errors += 1

    zcode_result = sync_zcode(config, verbose=verbose)
    scanned += zcode_result.get("scanned", 0)
    skipped += zcode_result.get("skipped", 0)
    synced += zcode_result.get("synced", 0)
    errors += zcode_result.get("errors", 0)

    if verbose:
        log_sync(
            f"scan complete: codex_scanned={scanned - zcode_result.get('scanned', 0)} "
            f"zcode_scanned={zcode_result.get('scanned', 0)} skipped={skipped} synced={synced} errors={errors}"
        )
    if errors == 0:
        mark_last_success()

    if scanned == 0 and not resolved_session_dir and zcode_result.get("scanned", 0) == 0:
        status = "no_sessions"
    elif errors > 0 and synced == 0:
        status = "error"
    elif errors > 0:
        status = "partial"
    else:
        status = "success"
    return {
        "status": status,
        "message": "Sync complete" if status == "success" else "Sync completed with errors",
        "session_dir": resolved_session_dir or "",
        "scanned": scanned,
        "skipped": skipped,
        "synced": synced,
        "errors": errors,
        "zcode": zcode_result,
    }


def daemon_mode(session_dir):
    while True:
        try:
            sync_mode(session_dir, verbose=False)
        except Exception as error:
            log_sync_error("daemon sync iteration failed", error)
        time.sleep(SYNC_INTERVAL_SECS)


def main():
    args = sys.argv[1:]
    json_output = False
    filtered_args = []
    for value in args:
        if value == "--json":
            json_output = True
        else:
            filtered_args.append(value)
    args = filtered_args
    codex_dir = ""

    if len(args) >= 1 and args[0] == "--summary":
        config = load_config() or {}
        if len(args) >= 2:
            codex_dir = args[1]
        summary_mode(codex_dir, verbose=True)
        return 0

    if len(args) >= 2 and args[0] == "--diagnose-date":
        config = load_config() or {}
        date_str = args[1]
        if len(args) >= 3:
            codex_dir = args[2]
        resolved_dir = resolve_session_dir(codex_dir, config)
        if not resolved_dir:
            log_sync("diagnose aborted: no Codex sessions directory found")
            emit_json({"source": "codex", "dates": [], "scan_roots": []})
            return 0
        diagnose_mode(resolved_dir, [date_str])
        return 0

    if len(args) >= 3 and args[0] == "--diagnose-range":
        config = load_config() or {}
        start_date = args[1]
        end_date = args[2]
        if len(args) >= 4:
            codex_dir = args[3]
        resolved_dir = resolve_session_dir(codex_dir, config)
        if not resolved_dir:
            log_sync("diagnose aborted: no Codex sessions directory found")
            emit_json({"source": "codex", "dates": [], "scan_roots": []})
            return 0
        diagnose_mode(resolved_dir, list(iter_dates(start_date, end_date)))
        return 0

    if len(args) >= 1 and args[0] == "--sync":
        if len(args) >= 2:
            codex_dir = args[1]
        result = sync_mode(codex_dir, verbose=True)
        if json_output:
            emit_json(result)
        if result["status"] in ("success", "partial", "no_sessions", "no_session_dir", "skipped"):
            return 0
        return 1

    if len(args) >= 1 and args[0] == "--daemon":
        if len(args) >= 2:
            codex_dir = args[1]
        daemon_mode(codex_dir)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
