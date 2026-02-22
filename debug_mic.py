import sounddevice as sd
import numpy as np

print("Available audio input devices:")
print(sd.query_devices())
print(f"\nDefault input device: {sd.default.device[0]} - {sd.query_devices(sd.default.device[0])['name']}")

print("\nRecording 3 seconds... SPEAK NOW")
audio = sd.rec(int(3 * 16000), samplerate=16000, channels=1, dtype='float32')
sd.wait()

max_vol = np.max(np.abs(audio))
rms = np.sqrt(np.mean(audio**2))
print(f"\nMax volume:  {max_vol:.4f}")
print(f"RMS volume:  {rms:.4f}")

if rms < 0.001:
    print("WARNING: Audio is nearly silent - wrong microphone or mic not working")
else:
    print("OK: Audio captured successfully")
