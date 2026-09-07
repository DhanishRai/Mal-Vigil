import os
import time
import subprocess
import lightgbm as lgb
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from extractor import extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "malware_lgbm.txt")
TARGET_EXTENSIONS = ('.exe', '.dll', '.scr')

def send_alert(title, message):
    """Sends a native desktop notification on Linux via notify-send."""
    try:
        subprocess.run(["notify-send", "-u", "critical", title, message], check=False)
    except Exception:
        pass

class BinaryWatcher(FileSystemEventHandler):
    def __init__(self, bst_model):
        self.bst = bst_model

    def on_created(self, event):
        if event.is_directory or not event.src_path.lower().endswith(TARGET_EXTENSIONS):
            return

        file_path = event.src_path
        file_name = os.path.basename(file_path)

        # Allow incoming download stream to finish writing
        time.sleep(1.5)
        if not os.path.exists(file_path):
            return

        # 1. Feature Extraction & Model Inference
        features = extract_features(file_path)
        pred_prob = float(self.bst.predict([features])[0])
        risk_percentage = int(pred_prob * 100)

        print(f"\n[SCAN] File: {file_name}")
        print(f"[SCAN] Calculated Risk Score: {risk_percentage}%")

        # 2. Risk Evaluation & Soft Quarantine
        if risk_percentage >= 50:
            quarantine_path = file_path + ".isolated"
            try:
                os.rename(file_path, quarantine_path)
                print(f"[ACTION] 🚨 Soft-quarantined: {file_name} -> {os.path.basename(quarantine_path)}")
                send_alert(
                    "🛡️ Mal-Vigil: Threat Intercepted",
                    f"'{file_name}' flagged as suspicious ({risk_percentage}% risk). File neutralized."
                )
            except OSError as err:
                print(f"[ERROR] Could not isolate file: {err}")
        else:
            print(f"[PASS] File verified clean: {file_name}")

def main():
    if not os.path.exists(MODEL_PATH):
        print("Model weights not found. Run 'python train_model.py' first.")
        return

    bst = lgb.Booster(model_file=MODEL_PATH)
    downloads_folder = os.path.expanduser("~/Downloads")

    observer = Observer()
    handler = BinaryWatcher(bst)
    observer.schedule(handler, path=downloads_folder, recursive=False)
    observer.start()

    print("==================================================")
    print("🛡️  Mal-Vigil Daemon Active (Linux)")
    print(f"📁 Monitoring: {downloads_folder}")
    print("Press Ctrl+C to stop.")
    print("==================================================")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()