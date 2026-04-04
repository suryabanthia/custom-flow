"""
Custom Flow — Voice dictation for Windows and macOS

Hold the hotkey (default: Right Alt / Right Option) → speak → release →
cleaned text is injected into whatever text box is currently focused.

Setup:
    1. Copy .env.example to .env and add your API keys
    2. Run: python main.py          (or double-click CustomFlow.exe on Windows)
    3. Right-click the pill overlay to add to startup or quit

CLI flags:
    python main.py --install      # Add to startup (Windows & macOS)
    python main.py --uninstall    # Remove from startup
"""

import argparse
import base64
import ctypes
import io
import json
import logging
import math
import os
import plistlib
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.messagebox as tk_msg

# ── Platform detection ───────────────────────────────────────────────────────────
_IS_WIN = sys.platform == "win32"
_IS_MAC = sys.platform == "darwin"

if _IS_WIN:
    import ctypes.wintypes

import numpy as np
import sounddevice as sd
import soundfile as sf
from deepgram import DeepgramClient
from deepgram.core.events import EventType
from deepgram.extensions.types.sockets import (
    ListenV1ControlMessage,
    ListenV1ResultsEvent,
)
from dotenv import load_dotenv
from openai import OpenAI
from pynput import keyboard
from pynput.keyboard import Controller as KbController, Key as KbKey

try:
    import pyperclip
    _HAS_PYPERCLIP = True
except ImportError:
    _HAS_PYPERCLIP = False


# ── Windows DPAPI Encryption (Windows-only) ─────────────────────────────────────
# Uses CryptProtectData/CryptUnprotectData — tied to the current Windows user.
# On macOS/Linux the keys live only in .env (no OS-level encryption needed).

if _IS_WIN:
    class _DPAPI:
        """Zero-dependency Windows Data Protection API wrapper."""

        class _BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_byte)),
            ]

        _protect = ctypes.windll.crypt32.CryptProtectData
        _unprotect = ctypes.windll.crypt32.CryptUnprotectData
        _local_free = ctypes.windll.kernel32.LocalFree

        @classmethod
        def encrypt(cls, data: bytes) -> bytes:
            blob_in = cls._BLOB(len(data), (ctypes.c_byte * len(data))(*data))
            blob_out = cls._BLOB()
            if not cls._protect(
                ctypes.byref(blob_in), None, None, None, None, 0,
                ctypes.byref(blob_out),
            ):
                raise OSError("DPAPI CryptProtectData failed")
            ptr = ctypes.cast(blob_out.pbData, ctypes.c_void_p)
            result = ctypes.string_at(ptr, blob_out.cbData)
            cls._local_free(blob_out.pbData)
            return result

        @classmethod
        def decrypt(cls, data: bytes) -> bytes:
            blob_in = cls._BLOB(len(data), (ctypes.c_byte * len(data))(*data))
            blob_out = cls._BLOB()
            if not cls._unprotect(
                ctypes.byref(blob_in), None, None, None, None, 0,
                ctypes.byref(blob_out),
            ):
                raise OSError("DPAPI CryptUnprotectData failed")
            ptr = ctypes.cast(blob_out.pbData, ctypes.c_void_p)
            result = ctypes.string_at(ptr, blob_out.cbData)
            cls._local_free(blob_out.pbData)
            return result


# ── Platform-aware data directory ────────────────────────────────────────────────

if _IS_WIN:
    _DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""), "CustomFlow")
elif _IS_MAC:
    _DATA_DIR = os.path.join(os.path.expanduser("~"), "Library",
                             "Application Support", "CustomFlow")
else:
    _DATA_DIR = os.path.join(os.path.expanduser("~"), ".config", "CustomFlow")

_KEYS_FILE = os.path.join(_DATA_DIR, "keys.enc")


_WIN_USERNAME_RE = re.compile(r'^[A-Za-z0-9._\-@ ]+$')


def _win_username() -> str:
    """Return the current Windows username, validated to safe characters."""
    name = os.environ.get("USERNAME", "")
    if not _WIN_USERNAME_RE.match(name):
        raise ValueError(f"USERNAME contains unexpected characters: {name!r}")
    return name


def _save_encrypted_keys(deepgram_key: str, cerebras_key: str):
    """Persist API keys. On Windows: DPAPI-encrypted. Otherwise: no-op (use .env)."""
    if not _IS_WIN:
        return
    os.makedirs(_DATA_DIR, exist_ok=True)
    payload = json.dumps({"d": deepgram_key, "c": cerebras_key}).encode("utf-8")
    encrypted = _DPAPI.encrypt(payload)  # type: ignore[name-defined]
    with open(_KEYS_FILE, "wb") as f:
        f.write(encrypted)
    try:
        subprocess.run(
            ["icacls", _KEYS_FILE, "/inheritance:r",
             "/grant:r", f"{_win_username()}:F"],
            capture_output=True,
        )
    except ValueError as e:
        logging.error(f"[security] icacls skipped: {e}")


def _load_encrypted_keys() -> tuple[str, str]:
    """Load and decrypt API keys. Returns ("", "") on any failure or non-Windows."""
    if not _IS_WIN or not os.path.isfile(_KEYS_FILE):
        return "", ""
    try:
        with open(_KEYS_FILE, "rb") as f:
            encrypted = f.read()
        payload = json.loads(_DPAPI.decrypt(encrypted).decode("utf-8"))  # type: ignore[name-defined]
        return payload.get("d", ""), payload.get("g", "")
    except Exception:
        return "", ""


# ── Error Logging (captures silent crashes in .exe mode) ────────────────────────

_LOG_DIR = _DATA_DIR
os.makedirs(_LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(_LOG_DIR, "error.log"),
    level=logging.ERROR,
    format="%(asctime)s %(message)s",
)

# Sanitize log records so API keys never reach the log file
class _SanitizeFilter(logging.Filter):
    _pat = re.compile(r"(gsk_|sk-|sk_live_|key[_-]?)[A-Za-z0-9]{16,}", re.I)
    def filter(self, record):
        record.msg = self._pat.sub("[REDACTED]", str(record.msg))
        record.args = ()
        return True

logging.getLogger().addFilter(_SanitizeFilter())


# ── Configuration ───────────────────────────────────────────────────────────────

def _find_env_file() -> str:
    paths_to_check = []
    
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        paths_to_check.append(os.path.join(exe_dir, ".env"))
        cwd = os.getcwd()
        paths_to_check.append(os.path.join(cwd, ".env"))
        if hasattr(sys, "_MEIPASS"):
            paths_to_check.append(os.path.join(sys._MEIPASS, ".env"))
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        paths_to_check.append(os.path.join(script_dir, ".env"))
    
    for path in paths_to_check:
        if os.path.isfile(path):
            return path
    
    return paths_to_check[0]


_ENV_FILE = _find_env_file()
_BASE_DIR = os.path.dirname(_ENV_FILE)
load_dotenv(_ENV_FILE)

# Restrict .env permissions to current user only (best-effort)
if os.path.isfile(_ENV_FILE):
    if _IS_WIN:
        try:
            result = subprocess.run(
                ["icacls", _ENV_FILE, "/inheritance:r",
                 "/grant:r", f"{_win_username()}:(R,W)"],
                capture_output=True,
            )
            if result.returncode != 0:
                logging.warning(f"[security] icacls on .env failed: {result.stderr.decode(errors='replace')}")
        except ValueError as e:
            logging.error(f"[security] icacls on .env skipped: {e}")
    else:
        try:
            os.chmod(_ENV_FILE, 0o600)
            if os.stat(_ENV_FILE).st_mode & 0o077 != 0:
                logging.warning("[security] .env is still world-readable after chmod")
        except OSError as e:
            logging.warning(f"[security] Failed to restrict .env permissions: {e}")

# Priority: encrypted store > .env > empty
_enc_dg, _enc_cerebras = _load_encrypted_keys()
DEEPGRAM_API_KEY: str = _enc_dg or os.getenv("DEEPGRAM_API_KEY", "")
CEREBRAS_API_KEY: str = _enc_cerebras or os.getenv("CEREBRAS_API_KEY", "")

# Scrub key variables from module scope after client creation (done below)
_HOTKEY_RAW: str = os.getenv("HOTKEY", "right_alt").lower().replace(" ", "_")
# Validate against whitelist so the value is never used in a dangerous context
HOTKEY_NAME: str = _HOTKEY_RAW if _HOTKEY_RAW in (
    "right_alt", "alt_r", "alt_gr", "right_ctrl", "ctrl_r",
    "right_shift", "shift_r", "caps_lock", "scroll_lock",
) else "right_alt"
CEREBRAS_MODEL: str = os.getenv("CEREBRAS_MODEL", "llama-3.3-70b")
DEBUG: bool = os.getenv("VOICEFLOW_DEBUG", "").lower() == "true"

LLM_SYSTEM_PROMPT: str = os.getenv(
    "LLM_SYSTEM_PROMPT",
    (
        "You are a voice transcript post-processor. Clean raw speech into polished written text.\n\n"
        "CLEANUP:\n"
        "- Remove filler words: um, uh, like, you know, basically, right, I mean, sort of\n"
        "- Remove false starts, stutters, and repeated words\n"
        "- When the speaker corrects themselves (\"I want A, no B\"), keep only the final version\n"
        "- Fix grammar and punctuation. Do not over-punctuate\n\n"
        "FORMATTING RULES:\n"
        "- Use double line breaks (blank line) to separate paragraphs and distinct topics\n"
        "- For lists of items, steps, or options, ALWAYS format as bullet points or numbered lists:\n"
        "  * Use bullet points (-) for unordered lists of items, features, or examples\n"
        "  * Use numbered lists (1. 2. 3.) for sequential steps, instructions, or ranked items\n"
        "- Start each list item on a new line\n"
        "- For email formatting: greeting on its own line, blank line before body, closing on its own line\n"
        "- For questions followed by answers: put each Q&A pair on separate lines\n"
        "- Keep the speaker's natural tone and conversational style\n\n"
        "STRICT RULES:\n"
        "- Output ONLY the cleaned and formatted text\n"
        "- Never add information the speaker did not say\n"
        "- Never summarize or shorten — preserve the full meaning\n"
        "- Never add labels like \"Subject:\" or section headers\n"
        "- Never add quotes around the output\n"
        "- Never add markdown formatting like **bold** or *italic*\n"
        "- If unsure about a word, keep the original"
    ),
)

SAMPLE_RATE = 16_000   # preferred; devices fall back to native rate if needed
# All rates PortAudio might need to try per device, in preference order:
# 16kHz is ideal for Deepgram; others cover WASAPI/WDM-KS at any Windows config.
_RATES_TO_TRY = [16000, 44100, 48000, 32000, 22050, 8000]
CHANNELS = 1
MIN_RECORDING_SEC = 0.3
MAX_RECORDING_SEC = 300       # 5-minute hard cap
MAX_TRANSCRIPT_LEN = 10_000   # Characters — reject abnormally long transcripts
# Worst case: 48kHz × float32 (4 bytes) × 5 min = ~55 MB. This covers all
# sample rates and is checked before sending to Deepgram.
MAX_AUDIO_BYTES = 48000 * 4 * MAX_RECORDING_SEC

_SKIP_MIC = {"stereo mix", "loopback", "what u hear",
             "wave out", "pc speaker", "primary sound capture"}


# ── Security Helpers ─────────────────────────────────────────────────────────────

_KEY_PATTERN = re.compile(r"(gsk_|sk-|sk_live_|key[_-]?)[A-Za-z0-9]{16,}", re.I)


def _sanitize_error(msg: str) -> str:
    """Strip anything that looks like an API key from error messages."""
    return _KEY_PATTERN.sub("[REDACTED]", str(msg))


def _sanitize_text(text: str) -> str:
    """Remove control characters except newline and tab."""
    return "".join(c for c in text if c in ("\n", "\t") or ord(c) >= 32)


def _validate_transcript(text: str) -> str:
    """Validate and sanitize a transcript before processing."""
    if not isinstance(text, str):
        raise TypeError("Transcript must be a string")
    if "\x00" in text:
        raise ValueError("Transcript contains null bytes")
    if len(text) > MAX_TRANSCRIPT_LEN:
        raise ValueError(f"Transcript too long ({len(text)} chars, max {MAX_TRANSCRIPT_LEN})")
    return _sanitize_text(text.strip())


# ── Reusable API Clients ────────────────────────────────────────────────────────

_deepgram: DeepgramClient | None = (
    DeepgramClient(api_key=DEEPGRAM_API_KEY) if DEEPGRAM_API_KEY else None
)
_cerebras: OpenAI | None = (
    OpenAI(
        api_key=CEREBRAS_API_KEY,
        base_url="https://api.cerebras.ai/v1",
        timeout=30.0,
    ) if CEREBRAS_API_KEY else None
)

# Scrub plaintext keys from module globals after clients are built
DEEPGRAM_API_KEY = "[loaded]" if _deepgram else ""
CEREBRAS_API_KEY = "[loaded]" if _cerebras else ""
_enc_dg = _enc_cerebras = ""


# ── Mic Utilities ───────────────────────────────────────────────────────────────

def _mic_candidates() -> list[int]:
    """
    Return all usable input device IDs, ordered by API preference.
    We include WDM-KS and all duplicates so Bluetooth headsets are not missed.
    The probe RMS will pick the device actually receiving audio.
    """
    # API preference order: WASAPI first (best quality), then DirectSound, MME, WDM-KS last
    _API_RANK = {"Windows WASAPI": 0, "Windows DirectSound": 1,
                 "MME": 2, "Windows WDM-KS": 3}

    candidates: list[tuple[int, int]] = []  # (dev_id, rank)
    for i, dev in enumerate(sd.query_devices()):
        if dev["max_input_channels"] < 1:
            continue
        name = dev["name"].lower()
        if any(kw in name for kw in _SKIP_MIC):
            continue
        hostapi = sd.query_hostapis(dev["hostapi"])["name"]
        rank = _API_RANK.get(hostapi, 99)
        candidates.append((i, rank))

    # Sort by API quality (WASAPI first), then by device id
    candidates.sort(key=lambda x: (x[1], x[0]))
    return [dev_id for dev_id, _ in candidates]


# ── Hotkey Mapping ──────────────────────────────────────────────────────────────

_alt_gr = getattr(keyboard.Key, "alt_gr", keyboard.Key.alt_r)

HOTKEY_MAP = {
    "right_alt":   keyboard.Key.alt_r,
    "alt_r":       keyboard.Key.alt_r,
    "alt_gr":      _alt_gr,
    "right_ctrl":  keyboard.Key.ctrl_r,
    "ctrl_r":      keyboard.Key.ctrl_r,
    "right_shift": keyboard.Key.shift_r,
    "shift_r":     keyboard.Key.shift_r,
    "caps_lock":   keyboard.Key.caps_lock,
    "scroll_lock": getattr(keyboard.Key, "scroll_lock", keyboard.Key.alt_r),
}

TARGET_KEY = HOTKEY_MAP.get(HOTKEY_NAME, keyboard.Key.alt_r)


def _key_matches(key) -> bool:
    """Match the configured hotkey, handling alt_gr / alt_r ambiguity on Windows."""
    if key == TARGET_KEY:
        return True
    # Windows sometimes reports AltGr as alt_r and vice-versa
    if TARGET_KEY in (_alt_gr, keyboard.Key.alt_r):
        return key in (_alt_gr, keyboard.Key.alt_r)
    return False


# ── Single-Instance Guard ────────────────────────────────────────────────────────
# Windows: named mutex. macOS/Linux: PID file in the data directory.
# Only checked when running as main, not on import.

_SINGLE_INSTANCE_EXIT = False
_MUTEX_HANDLE = None
_INSTANCE_CHECKED = False

def _check_single_instance():
    """Check if another instance is running. Returns True if should exit."""
    global _SINGLE_INSTANCE_EXIT, _MUTEX_HANDLE, _INSTANCE_CHECKED
    
    if _INSTANCE_CHECKED:
        return _SINGLE_INSTANCE_EXIT
    _INSTANCE_CHECKED = True
    
    # Temporarily disabled for debugging
    return False
    
    if _IS_WIN:
        _MUTEX_NAME = "CF_Final_20260225_v5_MTX"
        _MUTEX_HANDLE = ctypes.windll.kernel32.CreateMutexW(None, False, _MUTEX_NAME)
        if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            _SINGLE_INSTANCE_EXIT = True
    else:
        import atexit
        _PID_FILE = os.path.join(_DATA_DIR, "customflow.pid")
        os.makedirs(_DATA_DIR, exist_ok=True)
        try:
            if os.path.isfile(_PID_FILE):
                _old_pid = int(open(_PID_FILE).read().strip())
                try:
                    os.kill(_old_pid, 0)   # check if process is alive
                    _SINGLE_INSTANCE_EXIT = True
                except OSError:
                    pass  # stale PID — overwrite
            if not _SINGLE_INSTANCE_EXIT:
                with open(_PID_FILE, "w") as _pf:
                    _pf.write(str(os.getpid()))
                atexit.register(lambda: os.unlink(_PID_FILE) if os.path.isfile(_PID_FILE) else None)
        except Exception:
            pass
    
    return _SINGLE_INSTANCE_EXIT


# ── Shared State ────────────────────────────────────────────────────────────────

_recording_lock = threading.Lock()
is_recording = False
stop_recording_event = threading.Event()
# maxsize=1: only queue one recording at a time; ignore rapid key-mashing
event_queue: queue.Queue = queue.Queue(maxsize=1)

# Timestamps of last press and release — used to detect fast press+release
# races without a "stuck" flag. Float writes are GIL-protected in CPython.
_hotkey_pressed_at: float = 0.0
_hotkey_released_at: float = 0.0


# ── DPI Awareness + Screen Geometry ─────────────────────────────────────────────

# Tell Windows this process is DPI-aware so coordinates are in physical pixels.
# Without this, on a 150%-scaled screen the pill lands in the wrong corner.
if _IS_WIN:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # Per-monitor DPI aware
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()   # Fallback (Win 7+)
        except Exception:
            pass

    class _RECT(ctypes.Structure):
        _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                    ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


def _get_work_area(root: tk.Tk | None = None) -> dict:
    """Return the usable screen area (excludes taskbar on Windows, estimates on macOS)."""
    if _IS_WIN:
        rect = _RECT()
        SPI_GETWORKAREA = 0x0030
        ctypes.windll.user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(rect), 0)
        return {"left": rect.left, "top": rect.top,
                "right": rect.right, "bottom": rect.bottom}
    else:
        # macOS / Linux: use tkinter screen dimensions when available.
        # macOS has a ~25px menu bar at top and ~70px Dock at bottom (approximate).
        if root is not None:
            w = root.winfo_screenwidth()
            h = root.winfo_screenheight()
        else:
            w, h = 1920, 1080  # safe fallback
        return {"left": 0, "top": 25, "right": w, "bottom": h - 70}


# ── Overlay Widget ──────────────────────────────────────────────────────────────
#
# Compact floating pill with SuryaGenix palette.
# The label always reads "Custom Flow" — state is communicated entirely
# through the left-side indicator animation and background colour shift:
#
#   Idle:       maroon dot ●          cream bg
#   Recording:  bouncing audio bars   orange bg
#   Processing: sequential dot pulse  tan bg
#   Error:      flash maroon, "!" icon

class Overlay:
    """Compact floating pill overlay — state shown via animation, not text."""

    W, H = 186, 38
    R = 19   # H/2 → perfect semicircle ends

    # (bg, fg, border)
    PALETTE = {
        "idle":       ("#EDE4D8", "#6D1A00", "#D4C9BC"),
        "recording":  ("#E87B1E", "#FFFFFF", "#C8680F"),
        "processing": ("#DEB887", "#6D1A00", "#C9A36F"),
        "error":      ("#6D1A00", "#EDE4D8", "#4A1100"),
    }

    LABEL = "Custom Flow"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Custom Flow")
        self.root.overrideredirect(True)
        self.root.attributes("-topmost", True)

        # Chroma-key colour used to punch transparent holes in the corners.
        # Must not appear anywhere in the pill palette.
        _KEY = "#010203"
        self.root.configure(bg=_KEY)

        # Position pill using the actual work area
        # (handles taskbar on Windows, menu bar + Dock on macOS).
        wa = _get_work_area(root)
        x = wa["right"] - self.W - 20
        y = wa["bottom"] - self.H - 12
        self.root.geometry(f"{self.W}x{self.H}+{x}+{y}")

        self.canvas = tk.Canvas(
            root, width=self.W, height=self.H,
            bg=_KEY, highlightthickness=0, bd=0,
        )
        self.canvas.pack()

        # Make the key colour transparent so the rectangular corners are
        # invisible. -alpha is intentionally omitted here: combining
        # -alpha with -transparentcolor on Windows causes the crash
        # 0xC0000142; full opacity with a chroma key is cleaner anyway.
        self.root.update_idletasks()
        try:
            self.root.attributes("-transparentcolor", _KEY)
        except tk.TclError:
            pass

        self._drag_x = self._drag_y = 0
        self.canvas.bind("<ButtonPress-1>", self._drag_start)
        self.canvas.bind("<B1-Motion>", self._drag_move)

        # Animation state
        self._state = "idle"
        self._anim_step = 0
        self._anim_id: str | None = None

        self._render("idle")

    # ── Drag ──

    def _drag_start(self, event):
        self._drag_x = event.x
        self._drag_y = event.y

    def _drag_move(self, event):
        try:
            dx = event.x - self._drag_x
            dy = event.y - self._drag_y
            x = self.root.winfo_x() + dx
            y = self.root.winfo_y() + dy
            self.root.geometry(f"+{x}+{y}")
        except tk.TclError:
            pass

    # ── Drawing helpers ──

    def _pill(self, x1, y1, x2, y2, r, **kw):
        pts = [
            x1 + r, y1,      x2 - r, y1,
            x2,     y1,      x2,     y1 + r,
            x2,     y2 - r,  x2,     y2,
            x2 - r, y2,      x1 + r, y2,
            x1,     y2,      x1,     y2 - r,
            x1,     y1 + r,  x1,     y1,
        ]
        return self.canvas.create_polygon(pts, smooth=True, **kw)

    # ── Core render ──

    def _render(self, state: str):
        self._cancel_anim()
        self.canvas.delete("all")
        self._state = state

        bg, fg, border = self.PALETTE[state]
        w, h, r = self.W, self.H, self.R

        # Keep window and canvas background = border colour so the tiny
        # rectangular corners outside the pill shape are invisible
        self.root.configure(bg=border)
        self.canvas.configure(bg=border)

        # Border pill
        self._pill(1, 1, w - 1, h - 1, r, fill=border, outline="")
        # Main pill (inset by 2px)
        self._pill(3, 3, w - 3, h - 3, r - 2, fill=bg, outline="")

        # Indicator area: centred at x=24
        icx, icy = 24, h // 2
        if state == "idle":
            # Static dot
            self.canvas.create_oval(
                icx - 4, icy - 4, icx + 4, icy + 4,
                fill=fg, outline="",
            )
        elif state == "error":
            # Exclamation mark
            self.canvas.create_text(
                icx, icy, text="!", fill=fg,
                font=("Segoe UI", 12, "bold"), anchor="center",
            )

        # Label — always "Custom Flow"
        self.canvas.create_text(
            w // 2 + 12, h // 2, text=self.LABEL, fill=fg,
            font=("Segoe UI", 10, "bold"), anchor="center",
        )

        # Kick off animations
        if state == "recording":
            self._anim_step = 0
            self._anim_bars()
        elif state == "processing":
            self._anim_step = 0
            self._anim_dots()

    # ── Recording animation: bouncing audio bars ──

    def _anim_bars(self):
        if self._state != "recording":
            return
        try:
            self._anim_step += 1
            self.canvas.delete("anim")
            cx, cy = 24, self.H // 2
            fg = "#FFFFFF"
            bar_w = 2.5
            gap = 5
            for i, offset in enumerate([-gap, 0, gap]):
                phase = self._anim_step * 0.22 + i * 1.3
                bar_h = 5 + 7 * abs(math.sin(phase))
                x = cx + offset
                self.canvas.create_rectangle(
                    x - bar_w / 2, cy - bar_h / 2,
                    x + bar_w / 2, cy + bar_h / 2,
                    fill=fg, outline="", tags="anim",
                )
            self._anim_id = self.root.after(45, self._anim_bars)
        except tk.TclError:
            pass

    # ── Processing animation: sequential dot pulse ──

    def _anim_dots(self):
        if self._state != "processing":
            return
        try:
            self._anim_step += 1
            self.canvas.delete("anim")
            cx, cy = 24, self.H // 2
            _, fg, _, = self.PALETTE["processing"]
            active_idx = (self._anim_step // 5) % 3
            gap = 7
            for i, offset in enumerate([-gap, 0, gap]):
                r = 3.5 if i == active_idx else 2
                color = fg if i == active_idx else "#C9A36F"
                x = cx + offset
                self.canvas.create_oval(
                    x - r, cy - r, x + r, cy + r,
                    fill=color, outline="", tags="anim",
                )
            self._anim_id = self.root.after(80, self._anim_dots)
        except tk.TclError:
            pass

    # ── Animation control ──

    def _cancel_anim(self):
        if self._anim_id is not None:
            try:
                self.root.after_cancel(self._anim_id)
            except (tk.TclError, ValueError):
                pass
            self._anim_id = None

    # ── Thread-safe public setters ──

    def _safe(self, fn):
        try:
            self.root.after(0, fn)
        except (tk.TclError, RuntimeError):
            pass

    def set_idle(self):
        self._safe(lambda: self._render("idle"))

    def set_recording(self):
        self._safe(lambda: self._render("recording"))

    def set_processing(self):
        self._safe(lambda: self._render("processing"))

    def set_error(self, msg: str = "Error"):
        self._safe(lambda: self._render("error"))
        try:
            self.root.after(3000, self.set_idle)
        except (tk.TclError, RuntimeError):
            pass


# ── Audio Recording ─────────────────────────────────────────────────────────────

PROBE_SEC = 1.0
_MIN_PROBE_RMS = 0.005
_USE_DEFAULT_IF_SILENT = True
_cached_device: tuple[int, int] | None = None


def _get_default_input_device() -> int | None:
    try:
        default_dev = sd.default.device[0]
        if default_dev is not None and default_dev >= 0:
            return int(default_dev)
    except Exception:
        pass
    return None


def _find_best_sample_rate(dev_id: int) -> int:
    try:
        native = int(sd.query_devices(dev_id)["default_samplerate"])
        for rate in [SAMPLE_RATE, native] + _RATES_TO_TRY:
            try:
                with sd.InputStream(samplerate=rate, channels=1, device=dev_id, dtype="float32"):
                    return rate
            except Exception:
                continue
        return native if native > 0 else SAMPLE_RATE
    except Exception:
        return SAMPLE_RATE


def _probe_for_best_device() -> tuple[int, int] | None:
    global _cached_device
    
    if _cached_device is not None:
        dev_id, rate = _cached_device
        try:
            with sd.InputStream(samplerate=rate, channels=1, device=dev_id, dtype="float32"):
                pass
            logging.error(f"[TRACE] mic probe   | using cached dev={dev_id} rate={rate}")
            return _cached_device
        except Exception:
            logging.error(f"[TRACE] mic probe   | cached dev={dev_id} failed, re-probing")
            _cached_device = None
    
    default_dev = _get_default_input_device()
    
    def test_device(dev_id: int, duration: float = 0.5) -> tuple[float, int]:
        """Test a device and return (rms, sample_rate)."""
        try:
            dev_info = sd.query_devices(dev_id)
            native_rate = int(dev_info["default_samplerate"])
            
            for rate in [16000, native_rate, 48000, 44100]:
                try:
                    audio = sd.rec(
                        int(duration * rate), samplerate=rate, 
                        channels=1, dtype="float32", device=dev_id
                    )
                    sd.wait()
                    # Handle potential overflow/NaN
                    audio = np.nan_to_num(audio, nan=0.0, posinf=1.0, neginf=-1.0)
                    audio = np.clip(audio, -1.0, 1.0)
                    rms = float(np.sqrt(np.mean(audio ** 2)))
                    return rms, rate
                except Exception:
                    continue
            return 0.0, 16000
        except Exception:
            return 0.0, 16000
    
    # Step 1: Try the system default device first
    if default_dev is not None:
        logging.error(f"[TRACE] mic probe   | testing default dev={default_dev}")
        rms, rate = test_device(default_dev, duration=0.5)
        logging.error(f"[TRACE] mic probe   | default dev={default_dev} rms={rms:.6f} rate={rate}")
        if rms >= _MIN_PROBE_RMS:
            logging.error(f"[TRACE] mic probe   | using default device (good signal)")
            _cached_device = (default_dev, rate)
            return default_dev, rate
    
    # Step 2: Get all candidates and probe them
    candidates = _mic_candidates()
    
    if default_dev is not None and default_dev not in candidates:
        candidates.insert(0, default_dev)
    
    if not candidates:
        logging.error("[TRACE] mic probe   | no candidates found")
        return None
    
    logging.error(f"[TRACE] mic probe   | probing {len(candidates)} devices...")
    
    # Test each device sequentially with longer duration for accuracy
    device_scores: list[tuple[int, int, float]] = []  # (dev_id, rate, rms)
    
    for dev_id in candidates:
        dev_info = sd.query_devices(dev_id)
        name = dev_info["name"].lower()
        
        # Skip known problematic devices
        if any(kw in name for kw in ["stereo mix", "loopback", "what u hear", 
                                      "wave out", "pc speaker", "primary sound capture"]):
            continue
        
        rms, rate = test_device(dev_id, duration=PROBE_SEC)
        
        if rms > 0.0001:  # Only log devices with some signal
            logging.error(f"[TRACE] mic probe   | dev={dev_id} rms={rms:.6f} rate={rate} name={dev_info['name'][:30]}")
        
        if rms >= _MIN_PROBE_RMS:
            # Bonus for USB devices (usually better microphones)
            if "usb" in name:
                rms *= 1.5
            device_scores.append((dev_id, rate, rms))
    
    if device_scores:
        # Sort by RMS (highest first)
        device_scores.sort(key=lambda x: x[2], reverse=True)
        best_id, best_rate, best_rms = device_scores[0]
        logging.error(f"[TRACE] mic probe   | selected dev={best_id} rms={best_rms:.6f} rate={best_rate}")
        _cached_device = (best_id, best_rate)
        return best_id, best_rate
    
    # Step 3: Fallback to default if nothing found
    if default_dev is not None:
        rate = _find_best_sample_rate(default_dev)
        logging.error(f"[TRACE] mic probe   | no good device found, using default dev={default_dev}")
        _cached_device = (default_dev, rate)
        return default_dev, rate
    
    logging.error("[TRACE] mic probe   | all devices silent or failed")
    return None


# ── Deepgram Real-Time Streaming ─────────────────────────────────────────────────
#
# Audio is streamed as 16-bit PCM chunks to Deepgram's WebSocket endpoint while
# the user is still speaking. Deepgram sends back interim and final transcript
# segments in real-time, so by the time the user releases the hotkey the
# transcript is already assembled — eliminating the post-release upload delay.

_AUDIO_GAIN = 2.0
_AGC_TARGET_RMS = 0.15
_AGC_MAX_GAIN = 8.0
_AGC_MIN_GAIN = 1.0
_AGC_ADJUSTMENT_RATE = 0.1
_AGC_SMOOTHING_FRAMES = 5


class AutomaticGainControl:
    def __init__(self, target_rms: float = _AGC_TARGET_RMS, 
                 max_gain: float = _AGC_MAX_GAIN, 
                 min_gain: float = _AGC_MIN_GAIN):
        self.target_rms = target_rms
        self.max_gain = max_gain
        self.min_gain = min_gain
        self.current_gain = _AUDIO_GAIN
        self.rms_history: list[float] = []
        self.smoothing_frames = _AGC_SMOOTHING_FRAMES

    def process(self, audio: np.ndarray) -> np.ndarray:
        if len(audio) == 0:
            return audio
        
        current_rms = float(np.sqrt(np.mean(audio ** 2)))
        
        if current_rms > 0.0001:
            self.rms_history.append(current_rms)
            if len(self.rms_history) > self.smoothing_frames:
                self.rms_history.pop(0)
            
            if len(self.rms_history) >= self.smoothing_frames:
                avg_rms = sum(self.rms_history) / len(self.rms_history)
                if avg_rms > 0.0001:
                    ideal_gain = self.target_rms / avg_rms
                    ideal_gain = max(self.min_gain, min(self.max_gain, ideal_gain))
                    self.current_gain = (
                        self.current_gain * (1 - _AGC_ADJUSTMENT_RATE) + 
                        ideal_gain * _AGC_ADJUSTMENT_RATE
                    )
        
        boosted = audio * self.current_gain
        return np.clip(boosted, -1.0, 1.0)


def _transcribe_batch(audio: np.ndarray, sample_rate: int) -> str:
    """
    Deepgram REST batch transcription — used as a fallback when the
    real-time WebSocket returns an empty transcript.
    """
    if _deepgram is None:
        return ""
    if audio.nbytes > MAX_AUDIO_BYTES:
        raise ValueError("Recording too long")
    buf = io.BytesIO()
    sf.write(buf, audio, sample_rate, format="WAV", subtype="PCM_16")
    response = _deepgram.listen.v1.media.transcribe_file(
        request=buf.getvalue(),
        model="nova-3",
        language="en",
        smart_format=True,
    )
    try:
        raw = response.results.channels[0].alternatives[0].transcript.strip()
        return _validate_transcript(raw)
    except (AttributeError, IndexError):
        return ""


_WS_RECONNECT_ATTEMPTS = 2
_WS_CONNECT_TIMEOUT = 10.0


def _stream_and_transcribe(dev_id: int, rate: int) -> str:
    if _deepgram is None:
        raise RuntimeError("Deepgram API key not configured — add DEEPGRAM_API_KEY to .env")

    transcript_parts: list[str] = []
    audio_chunks: list[np.ndarray] = []
    agc = AutomaticGainControl()
    agc_gains: list[float] = []
    ws_error: str | None = None

    for attempt in range(_WS_RECONNECT_ATTEMPTS):
        transcript_parts.clear()
        listener_done = threading.Event()
        ws_error = None
        
        try:
            with _deepgram.listen.v1.connect(
                model="nova-3",
                language="en",
                encoding="linear16",
                sample_rate=str(rate),
                interim_results="true",
                endpointing="300",
                utterance_end_ms="1000",
                smart_format="true",
            ) as ws:

                def on_message(event_data):
                    if isinstance(event_data, ListenV1ResultsEvent):
                        try:
                            t = event_data.channel.alternatives[0].transcript
                            if t and event_data.is_final:
                                transcript_parts.append(t)
                                if DEBUG:
                                    print(f"[deepgram-live] final: {t!r}")
                        except (AttributeError, IndexError):
                            pass

                def on_close(_):
                    listener_done.set()

                def on_error(exc):
                    nonlocal ws_error
                    ws_error = str(exc)
                    logging.error(f"[TRACE] deepgram ws  | error={_sanitize_error(str(exc))}")

                ws.on(EventType.MESSAGE, on_message)
                ws.on(EventType.CLOSE,   on_close)
                ws.on(EventType.ERROR,   on_error)

                listener_thread = threading.Thread(target=ws.start_listening, daemon=True)
                listener_thread.start()

                def audio_callback(indata: np.ndarray, frames: int, time_info, status):
                    mono = indata[:, 0]
                    audio_chunks.append(mono.copy())
                    agc_gains.append(agc.current_gain)
                    processed = agc.process(mono)
                    pcm = (processed * 32767).astype(np.int16).tobytes()
                    try:
                        ws._send(pcm)
                    except Exception as e:
                        logging.error(f"[TRACE] ws send error | {_sanitize_error(str(e))}")

                try:
                    with sd.InputStream(
                        samplerate=rate, channels=1, dtype="float32",
                        device=dev_id, callback=audio_callback,
                    ):
                        stop_recording_event.wait(timeout=MAX_RECORDING_SEC)
                finally:
                    try:
                        ws.send_control(ListenV1ControlMessage(type="CloseStream"))
                    except Exception:
                        pass

                listener_done.wait(timeout=5.0)
                
                full_text = " ".join(transcript_parts).strip()
                if full_text:
                    return _validate_transcript(full_text)
                    
                if ws_error and attempt < _WS_RECONNECT_ATTEMPTS - 1:
                    logging.error(f"[TRACE] ws attempt {attempt+1} failed, retrying...")
                    time.sleep(0.2)
                    continue
                    
        except Exception as e:
            logging.error(f"[TRACE] ws connection error (attempt {attempt+1}): {_sanitize_error(str(e))}")
            if attempt < _WS_RECONNECT_ATTEMPTS - 1:
                time.sleep(0.2)
                continue

    full_text = " ".join(transcript_parts).strip()
    if full_text:
        return _validate_transcript(full_text)

    if not audio_chunks:
        return ""
    logging.error("[TRACE] deepgram ws  | empty stream → batch fallback")
    try:
        raw_audio = np.concatenate(audio_chunks)
        avg_gain = sum(agc_gains) / len(agc_gains) if agc_gains else _AUDIO_GAIN
        audio_arr = np.clip(raw_audio * avg_gain, -1.0, 1.0)
        return _transcribe_batch(audio_arr, rate)
    except Exception as exc:
        logging.error(f"[TRACE] batch fallback | {_sanitize_error(str(exc))}")
        return ""


# ── Cerebras Streaming + Text Injection ─────────────────────────────────────────────

def clean_and_inject(raw: str, overlay: Overlay):
    if not raw:
        return
    if _cerebras is None:
        raise RuntimeError("Cerebras API key not configured — add CEREBRAS_API_KEY to .env")

    stream = _cerebras.chat.completions.create(
        model=CEREBRAS_MODEL,
        messages=[
            {"role": "system", "content": LLM_SYSTEM_PROMPT},
            {"role": "user", "content": raw},
        ],
        temperature=0.0,
        max_tokens=2048,
        stream=True,
    )

    first_chunk = True
    for chunk in stream:
        delta = chunk.choices[0].delta.content
        if delta:
            clean_delta = _sanitize_text(delta)
            if not clean_delta:
                continue
            if first_chunk:
                time.sleep(0.15)
                first_chunk = False
            inject_text(clean_delta)


# ── Text Injection ──────────────────────────────────────────────────────────────

_kb = KbController()


def inject_text(text: str):
    if not text:
        return
    try:
        time.sleep(0.1)
        for char in text:
            if char == "\n":
                _kb.press(KbKey.enter)
                _kb.release(KbKey.enter)
            elif char == "\t":
                _kb.press(KbKey.tab)
                _kb.release(KbKey.tab)
            else:
                _kb.type(char)
            time.sleep(0.01)
    except Exception as e:
        logging.error(f"[TRACE] inject error: {e}")


# ── Pipeline Worker ─────────────────────────────────────────────────────────────

_MIN_RACE_THRESHOLD_SEC = 0.05


def pipeline_worker(overlay: Overlay):
    global is_recording

    while True:
        try:
            event = event_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        if event == "quit":
            break
        if event != "start":
            continue

        device = None
        t_start = time.monotonic()
        
        try:
            with _recording_lock:
                is_recording = True
            stop_recording_event.clear()

            press_age = time.monotonic() - _hotkey_pressed_at
            release_age = time.monotonic() - _hotkey_released_at if _hotkey_released_at > 0 else float('inf')
            
            is_race = (
                _hotkey_released_at >= _hotkey_pressed_at and
                release_age < _MIN_RACE_THRESHOLD_SEC
            )
            
            logging.error(f"[TRACE] record start | press_age={press_age:.3f}s release_age={release_age:.3f}s is_race={is_race}")

            if is_race:
                with _recording_lock:
                    is_recording = False
                overlay.set_idle()
                continue

            overlay.set_recording()
            device = _probe_for_best_device()
        except Exception as exc:
            logging.error(f"[TRACE] probe error  | {_sanitize_error(str(exc))}")
            device = None
        finally:
            if device is None:
                with _recording_lock:
                    is_recording = False

        if stop_recording_event.is_set():
            overlay.set_idle()
            continue

        if device is None:
            overlay.set_error("No mic signal")
            continue

        dev_id, rate = device

        raw = ""
        duration = 0.0
        try:
            raw = _stream_and_transcribe(dev_id, rate)
            duration = time.monotonic() - t_start
            logging.error(f"[TRACE] stream done  | duration={duration:.2f}s transcript={raw!r}")
        except Exception as exc:
            logging.error(f"[TRACE] stream error | {_sanitize_error(str(exc))}")
            duration = time.monotonic() - t_start
        finally:
            with _recording_lock:
                is_recording = False

        if not raw or duration < MIN_RECORDING_SEC:
            if not raw and duration >= MIN_RECORDING_SEC:
                logging.error("[TRACE] deepgram    | empty transcript — set_error")
                overlay.set_error("Nothing heard")
            else:
                overlay.set_idle()
            continue

        overlay.set_processing()
        try:
            clean_and_inject(raw, overlay)
            logging.error("[TRACE] inject done | back to idle")
            overlay.set_idle()

        except (ConnectionError, TimeoutError) as exc:
            logging.error(f"[TRACE] network err  | {_sanitize_error(str(exc))}")
            overlay.set_error("Network error")
        except ValueError as exc:
            logging.error(f"[TRACE] value err    | {_sanitize_error(str(exc))}")
            overlay.set_error("Invalid input")
        except RuntimeError as exc:
            logging.error(f"[TRACE] config err   | {_sanitize_error(str(exc))}")
            overlay.set_error("Not configured")
        except Exception as exc:
            logging.error(f"[TRACE] unexpected   | {_sanitize_error(str(exc))}")
            overlay.set_error("Unexpected error")


# ── Keyboard Listener ───────────────────────────────────────────────────────────

_DEBOUNCE_SEC = 0.15   # AltGr bounces on release; ignore presses within this window


def on_press(key):
    global _hotkey_pressed_at
    try:
        if not _key_matches(key):
            return
        now = time.monotonic()
        # Debounce: the physical AltGr key bounces on release, generating a
        # phantom press ~10-20 ms later. Ignore presses within DEBOUNCE_SEC of
        # the last release so ghost recordings never reach the pipeline.
        if _hotkey_released_at > 0 and now - _hotkey_released_at < _DEBOUNCE_SEC:
            return
        _hotkey_pressed_at = now
        try:
            event_queue.put_nowait("start")
        except queue.Full:
            pass  # Already recording — ignore
    except Exception:
        pass


def on_release(key):
    global _hotkey_released_at
    try:
        if not _key_matches(key):
            return
        _hotkey_released_at = time.monotonic()
        # Always signal stop — no conditional on is_recording.
        stop_recording_event.set()
    except Exception:
        pass


# ── Install / Uninstall Auto-Start ──────────────────────────────────────────────

if _IS_WIN:
    _STARTUP_DIR = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "Start Menu", "Programs", "Startup",
    )
    _LNK_NAME = "CustomFlow.lnk"
    _LNK_DST = os.path.join(_STARTUP_DIR, _LNK_NAME)
    # For .py mode — VBS launcher
    _VBS_NAME = "start_voiceflow.vbs"
    _VBS_SRC = os.path.join(_BASE_DIR, _VBS_NAME)
    _VBS_DST = os.path.join(_STARTUP_DIR, _VBS_NAME)
elif _IS_MAC:
    _LAUNCH_AGENTS_DIR = os.path.join(os.path.expanduser("~"), "Library", "LaunchAgents")
    _PLIST_NAME = "com.customflow.app.plist"
    _PLIST_DST = os.path.join(_LAUNCH_AGENTS_DIR, _PLIST_NAME)


def _is_frozen() -> bool:
    """True when running as a PyInstaller .exe."""
    return getattr(sys, "frozen", False)


def _is_startup_installed() -> bool:
    """Return True if startup item is installed."""
    if _IS_WIN:
        return os.path.isfile(_LNK_DST) or os.path.isfile(_VBS_DST)
    if _IS_MAC:
        return os.path.isfile(_PLIST_DST)
    return False


def _show_toast(root: tk.Tk, message: str, ok: bool = True):
    """
    Show a small styled notification above the pill for 2.5 seconds.
    Uses a plain Toplevel — works correctly with overrideredirect windows.
    """
    try:
        toast = tk.Toplevel(root)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        toast.attributes("-alpha", 0.95)

        bg = "#3A7D3A" if ok else "#6D1A00"   # green for success, maroon for error
        fg = "#FFFFFF"

        lbl = tk.Label(
            toast, text=message, bg=bg, fg=fg,
            font=("Segoe UI", 9, "bold"), padx=18, pady=10,
            wraplength=260,
        )
        lbl.pack()

        toast.update_idletasks()
        tw = toast.winfo_reqwidth()
        th = toast.winfo_reqheight()
        # Position centered above the pill
        px = root.winfo_x()
        py = root.winfo_y()
        pw = root.winfo_width()
        x = px + (pw - tw) // 2
        y = py - th - 8
        toast.geometry(f"+{x}+{y}")
        toast.after(2500, toast.destroy)
    except tk.TclError:
        pass


def _install_startup(silent: bool = False) -> bool:
    """Add Custom Flow to startup. Returns True on success."""
    if _IS_WIN:
        if _is_frozen():
            exe_path = sys.executable
            work_dir = os.path.dirname(exe_path)
            # Use -EncodedCommand to avoid PowerShell injection via paths
            # containing backticks, $(), semicolons, or other PS metacharacters.
            ps_script = (
                f"$lnk = '{_LNK_DST}'; "
                f"$exe = '{exe_path}'; "
                f"$dir = '{work_dir}'; "
                f"$ws = New-Object -ComObject WScript.Shell; "
                f"$s = $ws.CreateShortcut($lnk); "
                f"$s.TargetPath = $exe; "
                f"$s.WorkingDirectory = $dir; "
                f"$s.Save()"
            )
            ps_b64 = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", ps_b64],
                capture_output=True,
            )
            return result.returncode == 0
        else:
            if not os.path.isfile(_VBS_SRC):
                return False
            shutil.copy2(_VBS_SRC, _VBS_DST)
            return True
    elif _IS_MAC:
        # macOS auto-start via LaunchAgents plist.
        # Use plistlib (stdlib) to generate XML — prevents any injection
        # via paths that contain XML special characters (<, >, &, etc.).
        python_exec = sys.executable
        script_path = (
            sys.executable if _is_frozen()
            else os.path.abspath(__file__)
        )
        os.makedirs(_LAUNCH_AGENTS_DIR, exist_ok=True)
        # Verify the resolved path stays inside LaunchAgents (symlink safety)
        if not os.path.abspath(_PLIST_DST).startswith(os.path.abspath(_LAUNCH_AGENTS_DIR)):
            logging.error("[security] plist path escapes LaunchAgents dir — aborting")
            return False
        plist_dict = {
            "Label": "com.customflow.app",
            "ProgramArguments": [python_exec, script_path],
            "RunAtLoad": True,
            "KeepAlive": False,
        }
        try:
            with open(_PLIST_DST, "wb") as f:
                plistlib.dump(plist_dict, f)
            subprocess.run(["launchctl", "load", _PLIST_DST], capture_output=True)
            return True
        except Exception:
            return False
    return False


def _uninstall_startup() -> bool:
    """Remove Custom Flow from startup. Returns True if something was removed."""
    if _IS_WIN:
        removed = False
        for path in (_LNK_DST, _VBS_DST):
            if os.path.isfile(path):
                try:
                    os.remove(path)
                    removed = True
                except OSError:
                    pass
        return removed
    elif _IS_MAC:
        if os.path.isfile(_PLIST_DST):
            # Validate it's actually a regular file (not a symlink pointing elsewhere)
            if os.path.islink(_PLIST_DST):
                logging.error("[security] plist path is a symlink — aborting unload")
                return False
            subprocess.run(["launchctl", "unload", _PLIST_DST], capture_output=True)
            try:
                os.remove(_PLIST_DST)
                return True
            except OSError:
                pass
    return False


# ── Entry Point ─────────────────────────────────────────────────────────────────

def main():
    import datetime
    
    def _debug_log(msg):
        try:
            with open(os.path.join(_LOG_DIR, "error.log"), "a") as f:
                f.write(f"{datetime.datetime.now()} [DEBUG] {msg}\n")
        except:
            pass
    
    _debug_log("main() called")
    
    if _check_single_instance():
        _debug_log("single instance check failed - exiting")
        print("[CustomFlow] Another instance is already running.", file=sys.stderr)
        sys.exit(0)
    
    _debug_log("parsing args")
    parser = argparse.ArgumentParser(description="Custom Flow voice dictation")
    parser.add_argument("--install", action="store_true",
                        help="Add Custom Flow to Windows startup")
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove Custom Flow from Windows startup")
    args = parser.parse_args()

    if args.install:
        _install_startup()
        return
    if args.uninstall:
        _uninstall_startup()
        return

    _debug_log("checking API keys")
    if not _deepgram:
        print("[warn] DEEPGRAM_API_KEY not set. Add it to .env", file=sys.stderr)
    if not _cerebras:
        print("[warn] CEREBRAS_API_KEY not set. Add it to .env", file=sys.stderr)

    _debug_log("checking startup flag")
    # Auto-install to startup on very first launch (silent, no dialog)
    _STARTUP_FLAG = os.path.join(_LOG_DIR, "startup_installed")
    if not os.path.isfile(_STARTUP_FLAG):
        _debug_log("installing startup")
        _install_startup(silent=True)
        try:
            with open(_STARTUP_FLAG, "w") as _f:
                _f.write("1")
        except OSError:
            pass

    _debug_log("creating tkinter root")
    root = tk.Tk()
    _debug_log("creating overlay")
    overlay = Overlay(root)
    _debug_log("overlay created successfully")

    _debug_log("creating menu")
    # Right-click context menu on the overlay pill
    _menu = tk.Menu(root, tearoff=0,
                    bg="#EDE4D8", fg="#6D1A00", activebackground="#E87B1E",
                    activeforeground="#FFFFFF", font=("Segoe UI", 9))
    _debug_log("menu created")

    def _on_add_startup():
        ok = _install_startup()
        msg = "Added to startup  ✓\nCustom Flow will start on login." if ok \
              else "Startup install failed. Check error log."
        _show_toast(root, msg, ok=ok)

    def _on_remove_startup():
        removed = _uninstall_startup()
        msg = "Removed from startup  ✓\nCustom Flow will no longer auto-start." if removed \
              else "Not in startup — nothing to remove."
        _show_toast(root, msg, ok=removed)

    _menu.add_command(label="Add to Startup",    command=_on_add_startup)
    _menu.add_command(label="Remove from Startup", command=_on_remove_startup)
    _menu.add_separator()
    _menu.add_command(label="Quit", command=lambda: root.destroy())

    def _show_menu(event):
        try:
            _menu.tk_popup(event.x_root, event.y_root)
        finally:
            _menu.grab_release()

    overlay.canvas.bind("<Button-3>", _show_menu)   # Windows / Linux right-click
    overlay.canvas.bind("<Button-2>", _show_menu)   # macOS two-finger tap / right-click

    _debug_log("starting worker thread")
    worker = threading.Thread(target=pipeline_worker, args=(overlay,), daemon=True)
    worker.start()
    _debug_log("worker started")

    _debug_log("creating keyboard listener")
    def _make_listener():
        lst = keyboard.Listener(on_press=on_press, on_release=on_release)
        lst.daemon = True
        lst.start()
        return lst

    listener = _make_listener()
    _debug_log("keyboard listener started")
    _listener_ref = [listener]

    def _listener_watchdog():
        """Restart the keyboard listener if it ever dies silently."""
        while True:
            time.sleep(3.0)
            if not _listener_ref[0].is_alive():
                logging.warning("Keyboard listener died — restarting")
                try:
                    _listener_ref[0] = _make_listener()
                except Exception as exc:
                    logging.error(f"Failed to restart listener: {exc}")

    watchdog = threading.Thread(target=_listener_watchdog, daemon=True)
    watchdog.start()

    key_label = HOTKEY_NAME.replace("_", " ").title()
    print(f"[custom flow] Running. Hold [{key_label}] to record. Right-click pill to quit.")

    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        event_queue.put("quit")
        listener.stop()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        logging.exception("Fatal startup error")
        _log_path = os.path.join(_LOG_DIR, "error.log")
        try:
            tk_msg.showerror(
                "Custom Flow — Error",
                f"Custom Flow failed to start.\n\n"
                f"Error: {exc}\n\n"
                f"Details saved to:\n{_log_path}",
            )
        except Exception:
            pass
        sys.exit(1)
