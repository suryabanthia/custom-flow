# Custom Flow — Voice Dictation

Speak to type. Hold a hotkey, say what you want, release — the cleaned text appears wherever your cursor is.

Works on **Windows** and **macOS**.

---

## What It Does

1. You hold the hotkey (default: Right Alt on Windows / Right Option on Mac)
2. Speak — the pill in the bottom-right corner turns orange and animates
3. Release the hotkey — your speech is transcribed by Deepgram, then cleaned up by Cerebras
4. The polished text is typed into whatever app is focused (text editor, browser, Slack, etc.)

Lists, paragraphs, and punctuation are handled automatically. Filler words (um, uh, like) are removed.

---

## Step 1 — Download the Code

### Option A: Download ZIP (Easiest — No Git Required)

1. Open your web browser
2. Go to: **https://github.com/suryabanthia/custom-flow**
3. Click the green **"Code"** button
4. Click **"Download ZIP"**
5. Extract the ZIP file to any folder (e.g., `Documents\custom-flow`)

### Option B: Clone with Git (For Users with Git Installed)

Open Terminal (Mac) or Command Prompt (Windows) and run:
```bash
git clone https://github.com/suryabanthia/custom-flow.git
```

Then navigate into the folder:
```bash
cd custom-flow
```

---

## Step 2 — Install Python

### Windows

1. Download Python from **https://python.org/downloads**
2. Run the installer
3. **Important:** Check the box that says **"Add Python to PATH"**
4. Click "Install Now"

### macOS

Check if Python 3 is already installed:
```bash
python3 --version
```

If not, download it from **https://python.org/downloads** and install it.

---

## Step 3 — Install Dependencies

Open Terminal (Mac) or Command Prompt (Windows), navigate to the project folder, and run:

```bash
pip install -r requirements.txt
```

This installs all required packages. You only need to do this once.

---

## Step 4 — Add Your API Keys

### Get Your Keys (Both Are Free)

1. **Deepgram** — [console.deepgram.com](https://console.deepgram.com)
   - Sign up → Create a new API key

2. **Cerebras** — [console.cerebras.ai](https://console.cerebras.ai)
   - Sign up → Create a new API key

### Create the .env File

1. Copy `.env.example` to `.env`:
   - **Windows (Command Prompt):** `copy .env.example .env`
   - **Windows (PowerShell):** `Copy-Item .env.example .env`
   - **macOS:** `cp .env.example .env`

2. Open `.env` in any text editor (Notepad, TextEdit, VS Code, etc.)

3. Paste your API keys:
   ```
   DEEPGRAM_API_KEY=your_deepgram_key_here
   CEREBRAS_API_KEY=your_cerebras_key_here
   ```

---

## Step 5 — Run the App

```bash
python main.py
```

Or on Mac:
```bash
python3 main.py
```

The pill appears in the bottom-right corner — you're ready to dictate.

> **First run (macOS):**
> - macOS will ask for microphone permission — click **Allow**
> - If the hotkey doesn't respond, go to **System Settings → Privacy & Security → Accessibility** and enable Terminal

> **First run (Windows):**
> - Windows may ask for microphone permission — click **Allow**

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
- Grant microphone access: **Settings → Privacy → Microphone**
- `python main.py --install` adds it to Windows startup
- `python main.py --uninstall` removes it

### macOS
- Hotkey is **Right Option** (same physical key as Right Alt on Windows keyboards)
- Grant microphone access: **System Settings → Privacy & Security → Microphone → Terminal**
- Grant hotkey access: **System Settings → Privacy & Security → Accessibility → Terminal**
- `python3 main.py --install` adds it to login items
- `python3 main.py --uninstall` removes it

---

## Optional Settings (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `DEEPGRAM_API_KEY` | *(required)* | Deepgram API key |
| `CEREBRAS_API_KEY` | *(required)* | Cerebras API key |
| `HOTKEY` | `right_alt` | Hotkey to use. Options: `right_alt`, `right_ctrl`, `right_shift`, `caps_lock` |
| `CEREBRAS_MODEL` | `qwen-3-235b-a22b-instruct-2507` | Cerebras model for text cleanup |
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
- Check Task Manager (Windows) or Activity Monitor (Mac) for a running Python process
- Make sure you ran `pip install -r requirements.txt` successfully

**Hotkey doesn't respond on Mac:**
- Go to **System Settings → Privacy & Security → Accessibility** and enable Terminal

**"Module not found" error:**
- Make sure you ran: `pip install -r requirements.txt`
- On Mac, try: `pip3 install -r requirements.txt`

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `deepgram-sdk` | 5.3.2 | Speech-to-text transcription |
| `openai` | 1.61.0 | API client (used for Cerebras) |
| `sounddevice` | 0.5.5 | Microphone audio capture |
| `soundfile` | 0.13.1 | WAV audio encoding |
| `numpy` | 2.4.2 | Audio processing |
| `pynput` | 1.8.1 | Global keyboard hotkey listener |
| `python-dotenv` | 1.2.1 | Load `.env` config file |
