#!/usr/bin/env python3
"""
Sovereign Mesh - OCAP-oriented zero-knowledge cloud encryption wrapper (PROOF OF CONCEPT).

Watches a USB "hardware key" path for band_key.conf. While present, mounts the
rclone crypt remote (SovereignCrypt:) locally. When the key disappears (or the
path becomes unreadable), a dead-man switch kills rclone and force-unmounts.

NOT AUDITED. NOT CERTIFIED. See README.md.

Usage:
    python sovereign_wrapper.py [--config config.json] [--usb-path PATH]
                                [--mount POINT] [--remote NAME:] [--interval SEC]
                                [--headless]
"""
import argparse
import atexit
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------- defaults
SYSTEM = platform.system()  # 'Linux', 'Windows', 'Darwin'
DEFAULT_CONFIG = {
    "usb_key_path": "E:\\" if SYSTEM == "Windows" else "/media/{}/BANDKEY".format(os.environ.get("USER", "user")),
    "key_filename": "band_key.conf",
    "rclone_remote": "SovereignCrypt:",
    "mount_point": "S:" if SYSTEM == "Windows" else os.path.expanduser("~/SovereignVault"),
    "poll_interval": 0.5,
    "rclone_binary": "rclone",
    # If true, the first line of band_key.conf is passed to rclone as
    # RCLONE_CONFIG_PASS (decrypts an encrypted rclone.conf). Never logged.
    "use_key_as_config_pass": True,
    "extra_rclone_args": [],
}


def load_config(argv=None):
    p = argparse.ArgumentParser(description="Sovereign Mesh USB-key vault wrapper (PoC)")
    p.add_argument("--config", help="JSON config file overriding defaults")
    p.add_argument("--usb-path", dest="usb_key_path")
    p.add_argument("--key-file", dest="key_filename")
    p.add_argument("--remote", dest="rclone_remote")
    p.add_argument("--mount", dest="mount_point")
    p.add_argument("--interval", dest="poll_interval", type=float)
    p.add_argument("--rclone", dest="rclone_binary")
    p.add_argument("--headless", action="store_true", help="run watcher without GUI")
    a = p.parse_args(argv)
    cfg = dict(DEFAULT_CONFIG)
    if a.config:
        with open(a.config, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    for k in ("usb_key_path", "key_filename", "rclone_remote", "mount_point", "poll_interval", "rclone_binary"):
        v = getattr(a, k)
        if v is not None:
            cfg[k] = v
    return cfg, a.headless


# ---------------------------------------------------------------- core engine
class VaultEngine:
    """GUI-independent watcher + rclone controller."""

    def __init__(self, cfg, log=print, on_state=lambda unlocked: None):
        self.cfg = cfg
        self.log = log
        self.on_state = on_state
        self.proc = None
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None
        self.unlocked = False

    # -- helpers
    @property
    def key_path(self):
        return os.path.join(self.cfg["usb_key_path"], self.cfg["key_filename"])

    def key_present(self):
        try:
            return os.path.isfile(self.key_path) and os.access(self.key_path, os.R_OK)
        except OSError:
            return False  # unreadable path == key gone

    def platform_check(self):
        if SYSTEM == "Linux":
            if not (shutil.which("fusermount3") or shutil.which("fusermount")):
                self.log("[WARN] Linux: FUSE3 not found. Install 'fuse3' (apt/dnf).")
        elif SYSTEM == "Windows":
            self.log("[INFO] Windows: requires WinFsp (winget install WinFsp.WinFsp). "
                     "Mount point should be a free drive letter, e.g. S:")
        elif SYSTEM == "Darwin":
            self.log("[WARN] macOS is UNSUPPORTED/UNTESTED in this PoC (needs macFUSE).")
        else:
            self.log("[WARN] Unknown OS '%s' - untested." % SYSTEM)

    def rclone_path(self):
        return shutil.which(self.cfg["rclone_binary"]) or (
            self.cfg["rclone_binary"] if os.path.isfile(self.cfg["rclone_binary"]) else None)

    # -- watcher
    def arm(self):
        if self._thread and self._thread.is_alive():
            self.log("Watcher already armed.")
            return
        self.platform_check()
        if not self.rclone_path():
            self.log("[ERROR] rclone binary '%s' not found. Install rclone (https://rclone.org/install/)."
                     % self.cfg["rclone_binary"])
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._watch, name="KeyWatcher", daemon=True)
        self._thread.start()
        self.log("Hardware key watcher ARMED. Watching: %s" % self.key_path)

    def disarm(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.lock("watcher disarmed")
        self.log("Watcher DISARMED.")

    def _watch(self):
        while not self._stop.is_set():
            present = self.key_present()
            with self._lock:
                if present and not self.unlocked:
                    self.log("Hardware key detected.")
                    self.unlock()
                elif not present and self.unlocked:
                    self.log("!! Hardware key REMOVED - dead-man switch triggered.")
                    self.lock("key removed")
                elif self.unlocked and self.proc and self.proc.poll() is not None:
                    self.log("[WARN] rclone exited unexpectedly (code %s)." % self.proc.returncode)
                    self.lock("rclone exited")
            self._stop.wait(float(self.cfg["poll_interval"]))

    # -- mount / unmount
    def unlock(self):
        rclone = self.rclone_path()
        if not rclone:
            self.log("[ERROR] rclone not found; cannot mount.")
            return
        mp = self.cfg["mount_point"]
        if SYSTEM != "Windows":
            os.makedirs(mp, exist_ok=True)
        env = os.environ.copy()
        if self.cfg.get("use_key_as_config_pass"):
            try:
                with open(self.key_path, "r", encoding="utf-8") as f:
                    secret = f.readline().strip()
                if secret:
                    env["RCLONE_CONFIG_PASS"] = secret  # never logged
            except OSError as e:
                self.log("[ERROR] could not read key file: %s" % e.__class__.__name__)
                return
        cmd = [rclone, "mount", self.cfg["rclone_remote"], mp,
               "--vfs-cache-mode", "writes"] + list(self.cfg.get("extra_rclone_args", []))
        self.log("Launching: %s" % " ".join(cmd))  # cmd contains no secrets
        kw = {}
        if SYSTEM == "Windows":
            kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            self.proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, **kw)
        except OSError as e:
            self.log("[ERROR] failed to start rclone: %s" % e)
            return
        time.sleep(0.3)
        if self.proc.poll() is not None:
            self.log("[ERROR] rclone exited immediately (code %s). Check remote/config." % self.proc.returncode)
            self.proc = None
            return
        self.unlocked = True
        self.log("Vault UNLOCKED at %s (rclone pid %s)." % (mp, self.proc.pid))
        self.on_state(True)

    def lock(self, reason=""):
        with self._lock:
            had = self.unlocked or self.proc is not None
            if self.proc is not None:
                if self.proc.poll() is None:
                    self.log("Terminating rclone pid %s..." % self.proc.pid)
                    self.proc.kill()  # immediate; no graceful flush window
                    try:
                        self.proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self.log("[WARN] rclone did not exit after kill.")
                self.proc = None
            if had:
                self.force_unmount()
            self.unlocked = False
            if had:
                self.log("Vault LOCKED (%s)." % reason)
            self.on_state(False)

    def _run(self, cmd):
        try:
            r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            self.log("  %s -> exit %s" % (" ".join(cmd), r.returncode))
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired) as e:
            self.log("  %s -> %s" % (" ".join(cmd), e.__class__.__name__))
            return False

    def force_unmount(self):
        mp = self.cfg["mount_point"]
        self.log("Force-unmounting %s..." % mp)
        if SYSTEM == "Windows":
            # WinFsp mounts disappear when rclone dies; kill any stragglers.
            self._run(["taskkill", "/F", "/IM", "rclone.exe"])
            return
        if SYSTEM == "Linux":
            for tool in ("fusermount3", "fusermount"):
                if shutil.which(tool) and self._run([tool, "-uz", mp]):
                    return
            self._run(["umount", "-l", mp])
        else:
            self._run(["umount", "-f", mp])


# ---------------------------------------------------------------- GUI
def run_gui(cfg):
    try:
        import customtkinter as ctk
    except ImportError:
        print("customtkinter not installed: pip install customtkinter")
        sys.exit(1)

    ctk.set_appearance_mode("dark")
    app = ctk.CTk()
    app.title("Sovereign Mesh - Vault Controller (PoC)")
    app.geometry("720x480")

    status = ctk.CTkLabel(app, text="Vault Locked", text_color="#e53935",
                          font=ctk.CTkFont(size=28, weight="bold"))
    status.pack(pady=(20, 10))
    logbox = ctk.CTkTextbox(app, width=680, height=300)
    logbox.pack(padx=20, pady=10, fill="both", expand=True)
    logbox.configure(state="disabled")

    def log(msg):
        line = "[%s] %s\n" % (time.strftime("%H:%M:%S"), msg)
        def _do():
            logbox.configure(state="normal")
            logbox.insert("end", line)
            logbox.see("end")
            logbox.configure(state="disabled")
        app.after(0, _do)

    def on_state(unlocked):
        app.after(0, lambda: status.configure(
            text="Vault Unlocked" if unlocked else "Vault Locked",
            text_color="#43a047" if unlocked else "#e53935"))

    engine = VaultEngine(cfg, log=log, on_state=on_state)
    atexit.register(engine.lock, "app exit")

    row = ctk.CTkFrame(app, fg_color="transparent")
    row.pack(pady=10)
    ctk.CTkButton(row, text="Arm Hardware Key Watcher", command=engine.arm).pack(side="left", padx=8)
    ctk.CTkButton(row, text="Disarm & Lock", fg_color="#8e2424",
                  command=lambda: threading.Thread(target=engine.disarm, daemon=True).start()).pack(side="left", padx=8)

    def on_close():
        engine._stop.set()
        engine.lock("window closed")
        app.destroy()
    app.protocol("WM_DELETE_WINDOW", on_close)
    log("Sovereign Mesh PoC started on %s. Key file: %s" % (SYSTEM, engine.key_path))
    app.mainloop()


def run_headless(cfg):
    engine = VaultEngine(cfg, on_state=lambda u: print("STATE:", "UNLOCKED" if u else "LOCKED", flush=True))
    atexit.register(engine.lock, "exit")
    def _sig(*_):
        engine.disarm()
        sys.exit(0)
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)
    engine.arm()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    config, headless = load_config()
    (run_headless if headless else run_gui)(config)
