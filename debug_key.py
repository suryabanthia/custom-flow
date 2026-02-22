from pynput import keyboard

print("Press any key (Ctrl+C to stop)...")

def on_press(key):
    print(f"  pressed:  {key!r}")

def on_release(key):
    print(f"  released: {key!r}")
    if key == keyboard.Key.esc:
        return False

with keyboard.Listener(on_press=on_press, on_release=on_release) as l:
    l.join()
