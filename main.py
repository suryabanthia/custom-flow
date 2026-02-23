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
from dotenv import load_dotenv
from groq import Groq
from pynput import keyboard
from pynput.keyboard import Controller as KbController, Key as KbKey


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


def _save_encrypted_keys(deepgram_key: str, groq_key: str):
    """Persist API keys. On Windows: DPAPI-encrypted. Otherwise: no-op (use .env)."""
    if not _IS_WIN:
        return
    os.makedirs(_DATA_DIR, exist_ok=True)
    payload = json.dumps({"d": deepgram_key, "g": groq_key}).encode("utf-8")
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

# Find .env next to the .exe (frozen) or next to main.py (dev)
_BASE_DIR = (
    os.path.dirname(sys.executable)
    if getattr(sys, "frozen", False)
    else os.path.dirname(os.path.abspath(__file__))
)
_ENV_FILE = os.path.join(_BASE_DIR, ".env")
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
_enc_dg, _enc_groq = _load_encrypted_keys()
DEEPGRAM_API_KEY: str = _enc_dg or os.getenv("DEEPGRAM_API_KEY", "")
GROQ_API_KEY: str = _enc_groq or os.getenv("GROQ_API_KEY", "")

# Scrub key variables from module scope after client creation (done below)
_HOTKEY_RAW: str = os.getenv("HOTKEY", "right_alt").lower().replace(" ", "_")
# Validate against whitelist so the value is never used in a dangerous context
HOTKEY_NAME: str = _HOTKEY_RAW if _HOTKEY_RAW in (
    "right_alt", "alt_r", "alt_gr", "right_ctrl", "ctrl_r",
    "right_shift", "shift_r", "caps_lock", "scroll_lock",
) else "right_alt"
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")  # fast, non-reasoning
DEBUG: bool = os.getenv("VOICEFLOW_DEBUG", "").lower() == "true"

GROQ_SYSTEM_PROMPT: str = os.getenv(
    "GROQ_SYSTEM_PROMPT",
    (
        "You are a voice transcript post-processor. Clean raw speech into polished written text.\n\n"
        "CLEANUP:\n"
        "- Remove filler words: um, uh, like, you know, basically, right, I mean, sort of\n"
        "- Remove false starts, stutters, and repeated words\n"
        "- When the speaker corrects themselves (\"I want A, no B\"), keep only the final version\n"
        "- Fix grammar and punctuation. Do not over-punctuate\n\n"
        "FORMATTING:\n"
        "- If the speaker lists steps or items, format as a numbered or bulleted list\n"
        "- Use paragraphs for topic changes\n"
        "- Keep the speaker's natural tone and intent\n\n"
        "STRICT RULES:\n"
        "- Output ONLY the cleaned text\n"
        "- Never add information the speaker did not say\n"
        "- Never summarize or shorten — preserve the full meaning\n"
        "- Never add labels, quotes, or commentary\n"
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

_SKIP_MIC = {"stereo mix", "sound mapper", "loopback", "what u hear",
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
_groq: Groq | None = (
    Groq(api_key=GROQ_API_KEY, timeout=30.0) if GROQ_API_KEY else None
)

# Scrub plaintext keys from module globals after clients are built
DEEPGRAM_API_KEY = "[loaded]" if _deepgram else ""
GROQ_API_KEY = "[loaded]" if _groq else ""
_enc_dg = _enc_groq = ""


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

if _IS_WIN:
    _MUTEX_NAME = "CustomFlow_SingleInstance_Mutex"
    _mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        try:
            tk_msg.showwarning("Custom Flow", "Custom Flow is already running.")
        except Exception:
            pass
        sys.exit(0)
else:
    import atexit
    _PID_FILE = os.path.join(_DATA_DIR, "customflow.pid")
    os.makedirs(_DATA_DIR, exist_ok=True)
    try:
        if os.path.isfile(_PID_FILE):
            _old_pid = int(open(_PID_FILE).read().strip())
            try:
                os.kill(_old_pid, 0)   # check if process is alive
                try:
                    tk_msg.showwarning("Custom Flow", "Custom Flow is already running.")
                except Exception:
                    pass
                sys.exit(0)
            except OSError:
                pass  # stale PID — overwrite
        with open(_PID_FILE, "w") as _pf:
            _pf.write(str(os.getpid()))
        atexit.register(lambda: os.unlink(_PID_FILE) if os.path.isfile(_PID_FILE) else None)
    except Exception:
        pass


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
        self.root.attributes("-alpha", 0.96)

        # Use the idle border colour as window background so the tiny
        # canvas corners that fall outside the pill shape are invisible.
        # No -transparentcolor needed (and avoids Windows crash 0xC0000142).
        _idle_border = self.PALETTE["idle"][2]
        self.root.configure(bg=_idle_border)

        # Position pill using the actual work area
        # (handles taskbar on Windows, menu bar + Dock on macOS).
        wa = _get_work_area(root)
        x = wa["right"] - self.W - 20
        y = wa["bottom"] - self.H - 12
        self.root.geometry(f"{self.W}x{self.H}+{x}+{y}")

        self.canvas = tk.Canvas(
            root, width=self.W, height=self.H,
            bg=_idle_border, highlightthickness=0, bd=0,
        )
        self.canvas.pack()

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

PROBE_SEC = 0.3


def _to_mono(audio: np.ndarray) -> np.ndarray:
    """Flatten single-channel (or already-1D) audio to a 1D array."""
    if audio.ndim == 1:
        return audio
    return audio[:, 0]


def _record_from_device(dev_id: int, preferred_rate: int = SAMPLE_RATE) -> tuple[np.ndarray, int] | None:
    chunks: list[np.ndarray] = []
    native = int(sd.query_devices(dev_id)["default_samplerate"])

    def cb(indata, frames, time_info, status):
        chunks.append(indata.copy())

    used_rate = SAMPLE_RATE
    all_rates = list(dict.fromkeys([preferred_rate, SAMPLE_RATE, native] + _RATES_TO_TRY))
    for i, rate in enumerate(all_rates):
        chunks.clear()
        try:
            with sd.InputStream(
                samplerate=rate, channels=1, dtype="float32",
                device=dev_id, callback=cb,
            ):
                stop_recording_event.wait(timeout=MAX_RECORDING_SEC)
            used_rate = rate
            break  # success
        except Exception as e:
            logging.error(f"[TRACE] mic open err | dev={dev_id} rate={rate} {_sanitize_error(e)}")
            if i == len(all_rates) - 1:
                return None  # all rates exhausted

    if not chunks:
        return None
    return _to_mono(np.concatenate(chunks)), used_rate


def _probe_and_record() -> tuple[np.ndarray, int] | None:
    candidates = _mic_candidates()
    if not candidates:
        logging.error("[TRACE] mic probe   | no candidates found")
        return None

    buffers: dict[int, list[np.ndarray]] = {i: [] for i in candidates}
    rates: dict[int, int] = {}
    streams: dict[int, sd.InputStream] = {}

    def make_cb(dev_id: int):
        def cb(indata, frames, time_info, status):
            buffers[dev_id].append(indata.copy())
        return cb

    for dev_id in candidates:
        # Try 16kHz first; fall back through all common rates including the
        # device's native rate. This covers WASAPI endpoints configured at
        # 44100 Hz, 48000 Hz, or any other Windows Audio Engine setting.
        native = int(sd.query_devices(dev_id)["default_samplerate"])
        for rate in dict.fromkeys([SAMPLE_RATE, native] + _RATES_TO_TRY):
            try:
                rates[dev_id] = rate
                s = sd.InputStream(
                    samplerate=rate, channels=1, dtype="float32",
                    device=dev_id, callback=make_cb(dev_id),
                )
                s.start()
                streams[dev_id] = s
                logging.error(f"[TRACE] mic probe   | started dev={dev_id} rate={rate} ch=1")
                break
            except Exception as e:
                logging.error(f"[TRACE] mic probe   | skipped dev={dev_id} rate={rate} err={_sanitize_error(e)}")

    if not streams:
        logging.error("[TRACE] mic probe   | all devices failed")
        return None

    deadline = time.monotonic() + PROBE_SEC
    while time.monotonic() < deadline and not stop_recording_event.is_set():
        time.sleep(0.02)

    def rms_of(dev_id: int) -> float:
        c = buffers[dev_id]
        if not c:
            return 0.0
        return float(np.sqrt(np.mean(np.concatenate(c) ** 2)))

    best_id = max(streams, key=rms_of)
    logging.error(f"[TRACE] mic probe   | best dev={best_id} rms={rms_of(best_id):.6f} rate={rates[best_id]}")

    for dev_id, s in streams.items():
        if dev_id != best_id:
            s.stop()
            s.close()

    if not stop_recording_event.is_set():
        stop_recording_event.wait(timeout=MAX_RECORDING_SEC)

    streams[best_id].stop()
    streams[best_id].close()

    if not buffers[best_id]:
        return None
    return _to_mono(np.concatenate(buffers[best_id])), rates[best_id]


def record_audio() -> tuple[np.ndarray, int] | None:
    """Returns (audio_array, sample_rate) or None. Always probes for the active mic."""
    return _probe_and_record()


# ── Deepgram Transcription ──────────────────────────────────────────────────────

def transcribe(audio: np.ndarray, sample_rate: int = SAMPLE_RATE) -> str:
    if _deepgram is None:
        raise RuntimeError("Deepgram API key not configured — add DEEPGRAM_API_KEY to .env")

    # Audio size guard
    if audio.nbytes > MAX_AUDIO_BYTES:
        raise ValueError("Recording too long")

    buf = io.BytesIO()
    sf.write(buf, audio, sample_rate, format="WAV", subtype="PCM_16")
    audio_bytes = buf.getvalue()

    response = _deepgram.listen.v1.media.transcribe_file(
        request=audio_bytes,
        model="nova-3",
        language="en",
        smart_format=True,
    )
    try:
        raw = response.results.channels[0].alternatives[0].transcript.strip()
        return _validate_transcript(raw)
    except (AttributeError, IndexError):
        return ""


# ── Groq Streaming + Text Injection ─────────────────────────────────────────────

def clean_and_inject(raw: str, overlay: Overlay):
    if not raw:
        return
    if _groq is None:
        raise RuntimeError("Groq API key not configured — add GROQ_API_KEY to .env")

    # Reasoning models (like openai/gpt-oss-120b) consume tokens internally
    # for "thinking" before producing visible output. A low max_tokens budget
    # gets exhausted by reasoning, leaving nothing for the actual response.
    # We detect this by checking for known reasoning model name patterns.
    _REASONING_MODELS = {"gpt-oss", "reasoning", "think"}
    _is_reasoning = any(k in GROQ_MODEL.lower() for k in _REASONING_MODELS)
    _max_tokens = 16000 if _is_reasoning else 2048

    _FALLBACK_MODEL = "llama-3.1-8b-instant"
    models_to_try = [GROQ_MODEL]
    if GROQ_MODEL != _FALLBACK_MODEL:
        models_to_try.append(_FALLBACK_MODEL)

    for model in models_to_try:
        stream = _groq.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": GROQ_SYSTEM_PROMPT},
                {"role": "user", "content": raw},
            ],
            temperature=0.0,
            max_tokens=_max_tokens,
            stream=True,
        )

        first_chunk = True
        got_content = False
        for chunk in stream:
            delta = chunk.choices[0].delta.content
            if delta:
                clean_delta = _sanitize_text(delta)
                if not clean_delta:
                    continue
                if first_chunk:
                    time.sleep(0.15)
                    first_chunk = False
                got_content = True
                inject_text(clean_delta)

        if DEBUG:
            print(f"[groq] streaming complete (model={model}, got_content={got_content})")

        if got_content:
            break
        # Model returned empty — try fallback
        if DEBUG:
            print(f"[groq] model {model!r} returned empty, trying fallback")


# ── Text Injection ──────────────────────────────────────────────────────────────

_kb = KbController()


def inject_text(text: str):
    if not text:
        return
    for char in text:
        if char == "\n":
            _kb.press(KbKey.enter)
            _kb.release(KbKey.enter)
        elif char == "\t":
            _kb.press(KbKey.tab)
            _kb.release(KbKey.tab)
        else:
            _kb.type(char)


# ── Pipeline Worker ─────────────────────────────────────────────────────────────

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

        # ── Record ──
        try:
            with _recording_lock:
                is_recording = True
            stop_recording_event.clear()
            # Guard against race: if the key was released before we cleared
            # the event, re-signal immediately so recording doesn't hang.
            race = _hotkey_released_at >= _hotkey_pressed_at
            if race:
                stop_recording_event.set()
            logging.error(f"[TRACE] record start | pressed={_hotkey_pressed_at:.3f} released={_hotkey_released_at:.3f} race={race}")
            overlay.set_recording()
            t_start = time.monotonic()

            result = record_audio()
            duration = time.monotonic() - t_start
            if result is not None:
                audio, audio_rate = result
                rms = float(np.sqrt(np.mean(audio ** 2)))
            else:
                audio, audio_rate, rms = None, SAMPLE_RATE, -1
            logging.error(f"[TRACE] record done  | duration={duration:.2f}s audio={'None' if audio is None else audio.shape} rate={audio_rate} rms={rms:.6f}")
        except Exception as exc:
            logging.error(f"[TRACE] record error  | {_sanitize_error(exc)}")
            print(f"[error] Recording failed: {_sanitize_error(exc)}", file=sys.stderr)
            audio = None
            duration = 0
        finally:
            with _recording_lock:
                is_recording = False

        if audio is None or duration < MIN_RECORDING_SEC:
            overlay.set_idle()
            continue

        # ── Transcribe & stream ──
        overlay.set_processing()
        try:
            raw = transcribe(audio, audio_rate)
            logging.error(f"[TRACE] deepgram    | transcript={raw!r}")

            if not raw:
                logging.error("[TRACE] deepgram    | empty transcript — set_error")
                overlay.set_error("Nothing heard")
                continue

            clean_and_inject(raw, overlay)
            logging.error("[TRACE] inject done | back to idle")
            overlay.set_idle()

        except (ConnectionError, TimeoutError) as exc:
            logging.error(f"[TRACE] network err  | {_sanitize_error(exc)}")
            overlay.set_error("Network error")
        except ValueError as exc:
            logging.error(f"[TRACE] value err    | {_sanitize_error(exc)}")
            overlay.set_error("Invalid input")
        except RuntimeError as exc:
            logging.error(f"[TRACE] config err   | {_sanitize_error(exc)}")
            overlay.set_error("Not configured")
        except Exception as exc:
            logging.error(f"[TRACE] unexpected   | {_sanitize_error(exc)}")
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

    if not _deepgram:
        print("[warn] DEEPGRAM_API_KEY not set. Add it to .env", file=sys.stderr)
    if not _groq:
        print("[warn] GROQ_API_KEY not set. Add it to .env", file=sys.stderr)

    # Auto-install to startup on very first launch (silent, no dialog)
    _STARTUP_FLAG = os.path.join(_LOG_DIR, "startup_installed")
    if not os.path.isfile(_STARTUP_FLAG):
        _install_startup(silent=True)
        try:
            with open(_STARTUP_FLAG, "w") as _f:
                _f.write("1")
        except OSError:
            pass

    root = tk.Tk()
    overlay = Overlay(root)

    # Right-click context menu on the overlay pill
    _menu = tk.Menu(root, tearoff=0,
                    bg="#EDE4D8", fg="#6D1A00", activebackground="#E87B1E",
                    activeforeground="#FFFFFF", font=("Segoe UI", 9))

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

    worker = threading.Thread(target=pipeline_worker, args=(overlay,), daemon=True)
    worker.start()

    def _make_listener():
        lst = keyboard.Listener(on_press=on_press, on_release=on_release)
        lst.daemon = True
        lst.start()
        return lst

    listener = _make_listener()
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
