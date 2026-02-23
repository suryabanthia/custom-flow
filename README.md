# Custom Flow — Voice Dictation

Speak to type. Hold a hotkey, say what you want, release — the cleaned text appears wherever your cursor is.

Works on **Windows** and **macOS**.

---

## What It Does

1. You hold the hotkey (default: Right Alt on Windows / Right Option on Mac)
2. Speak — the pill in the bottom-right corner turns orange and animates
3. Release the hotkey — your speech is transcribed by Deepgram, then cleaned up by Groq
4. The polished text is typed into whatever app is focused (text editor, browser, Slack, etc.)

Lists, paragraphs, and punctuation are handled automatically. Filler words (um, uh, like) are removed.

---

## Setup — Windows

No Python needed. Just:

1. Download `CustomFlow.exe` and `.env` into the same folder
2. Open `.env` in Notepad and fill in your API keys:
   ```
   DEEPGRAM_API_KEY=your_deepgram_key_here
   GROQ_API_KEY=your_groq_key_here
   ```
3. Double-click `CustomFlow.exe`

That's it. The pill appears in the bottom-right corner — you're ready to dictate.

---

## Setup — macOS

Mac users need Python and a few packages installed first.

### Step 1 — Install Python

Check if Python 3 is already installed:
```bash
python3 --version
```

If not, download it from [python.org/downloads](https://www.python.org/downloads/) and install it.

### Step 2 — Install dependencies

Open Terminal and run:
```bash
pip3 install deepgram-sdk groq sounddevice soundfile numpy pynput python-dotenv
```

You only need to do this once.

### Step 3 — Add your API keys

In the project folder, copy the example config:
```bash
cp .env.example .env
```

Open `.env` in any text editor and fill in:
```
DEEPGRAM_API_KEY=your_deepgram_key_here
GROQ_API_KEY=your_groq_key_here
```

### Step 4 — Run

```bash
python3 main.py
```

The pill appears in the bottom-right corner — you're ready to dictate.

> **First run:** macOS will ask for microphone permission — click Allow.
> If the hotkey doesn't respond, go to **System Settings → Privacy & Security → Accessibility** and enable access for Terminal.

---

## Where to Get API Keys

Both are free — no credit card needed.

- **Deepgram:** [console.deepgram.com](https://console.deepgram.com) → Create a new API key
- **Groq:** [console.groq.com](https://console.groq.com) → API Keys → Create new

---

## Usage

| Action | Result |
|--------|--------|
| Hold **Right Alt** (Win) / **Right Option** (Mac) | Start recording — pill turns orange |
| Speak | Your voice is captured |
| Release the hotkey | Transcription begins (pill turns tan) |
| Done | Cleaned text is typed where your cursor is |

**Right-click** the pill to:
- Add to startup (auto-launches when you log in)
- Remove from startup
- Quit

---

## Platform Notes

### Windows
- The `.exe` has its own microphone privacy entry — no extra permissions needed
- `CustomFlow.exe --install` adds it to Windows startup automatically
- `CustomFlow.exe --uninstall` removes it

### macOS
- Hotkey is **Right Option** (same physical key as Right Alt on Windows keyboards)
- Grant microphone access: **System Settings → Privacy & Security → Microphone → Terminal**
- Grant hotkey access: **System Settings → Privacy & Security → Accessibility → Terminal**
- `python3 main.py --install` adds it to login items (auto-starts on login)
- `python3 main.py --uninstall` removes it

---

## Optional Settings (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `DEEPGRAM_API_KEY` | *(required)* | Deepgram API key |
| `GROQ_API_KEY` | *(required)* | Groq API key |
| `HOTKEY` | `right_alt` | Hotkey to use. Options: `right_alt`, `right_ctrl`, `right_shift`, `caps_lock` |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Groq model for text cleanup |
| `VOICEFLOW_DEBUG` | `false` | Set to `true` to print transcripts to the console |

---

## Troubleshooting

**Pill turns orange but no text appears:**
- Check the log file for errors:
  - Windows: `%LOCALAPPDATA%\CustomFlow\error.log`
  - Mac: `~/Library/Application Support/CustomFlow/error.log`
- Confirm your API keys are correct in `.env`
- Make sure the app has microphone permission (see Platform Notes above)

**Text appears but is garbled:**
- Speak more slowly and clearly
- Check your microphone input level in system sound settings

**Pill doesn't appear:**
- Windows: check Task Manager for a running CustomFlow.exe
- Mac: check Activity Monitor for a running Python process

**Hotkey doesn't respond on Mac:**
- Go to **System Settings → Privacy & Security → Accessibility** and enable Terminal

---

## Dependencies (macOS only — Windows .exe bundles these automatically)

| Package | Version | Purpose |
|---------|---------|---------|
| `deepgram-sdk` | 5.3.2 | Speech-to-text transcription |
| `groq` | 1.0.0 | AI text cleanup |
| `sounddevice` | 0.5.5 | Microphone audio capture |
| `soundfile` | 0.13.1 | WAV audio encoding |
| `numpy` | 2.4.2 | Audio processing |
| `pynput` | 1.8.1 | Global keyboard hotkey listener |
| `python-dotenv` | 1.2.1 | Load `.env` config file |
