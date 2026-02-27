import keyboard
import requests
import time
import logging
import threading
import re
import os
import sys
import subprocess
import tempfile
import json
import base64
import hashlib
import pystray  # pip install pystray
from PIL import Image, ImageDraw

try:
    from PIL import ImageTk
except Exception:
    ImageTk = None

try:
    import tkinter as tk
    from tkinter import messagebox
except Exception:
    tk = None
    messagebox = None

try:
    from plyer import notification
except Exception:
    notification = None

try:
    from playsound import playsound  # optional
except Exception:
    playsound = None

try:
    import winsound
except Exception:
    winsound = None

try:
    import winreg
except Exception:
    winreg = None

# ==========================
# CONFIGURATION
# ==========================
API_KEY = "KkKf87BOncnOGwzjLBG8Isd87T42D1yOJJNoUMsrjmUkqSIxXmHG4XPZ07UQM0Pi"
API_PATH_EMPLOYEE = "/api/barcode-bridge/staff-attendance"
API_PATH_CLIENT = "/api/barcode-bridge/attendance"
API_PATH_AUTH = "/api/barcode-bridge/auth"
API_PATH_LOGIN_FALLBACK = "/api/login"
BASE_DOMAIN = "gym-engine.com"
DEFAULT_SUBDOMAIN = "demo"
DEBOUNCE_TIME = 1.5  # seconds to ignore duplicate scans
FREEZE_COOLDOWN = 10  # seconds to ignore repeated barcode scans
BARCODE_DELIMITER = "enter"
REQUEST_TIMEOUT = 10
MIN_BARCODE_LENGTH = 4
MAX_KEY_INTERVAL = 0.12  # scanner keys are usually very fast
RUN_IN_BACKGROUND = True
AUTO_ENABLE_STARTUP = True
STARTUP_VALUE_NAME = "GymBarcodeBridge"
STARTUP_TASK_NAME = "GymBarcodeBridge"
SHOW_STARTUP_TOAST = True
REQUIRE_ADMIN = True
APP_VERSION = "1.0.0"
UPDATE_CHECK_TIMEOUT = 15
DEFAULT_UPDATE_MANIFEST_URL = "https://raw.githubusercontent.com/shopnaill/gym-engine-bridge/main/updates/update-manifest.json"

DEFAULT_APP_SETTINGS = {
    "subdomain": DEFAULT_SUBDOMAIN,
    "installed_version": APP_VERSION,
    "setup_completed": False,
    "auth_phone": "",
    "auth_password_enc": "",
    "enable_employee_attendance": True,
    "enable_client_attendance": True,
    "enable_toast": True,
    "enable_sound": True,
    "enable_auto_update": True,
    "update_manifest_url": DEFAULT_UPDATE_MANIFEST_URL,
}

def pick_sound_file(primary_wav, fallback_mp3):
    base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    wav_path = os.path.join(base_dir, primary_wav)
    mp3_path = os.path.join(base_dir, fallback_mp3)
    if os.path.exists(wav_path):
        return wav_path
    if os.path.exists(mp3_path):
        return mp3_path
    return wav_path


SUCCESS_SOUND = pick_sound_file("success.wav", "success.mp3")
ERROR_SOUND = pick_sound_file("error.wav", "error.mp3")

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Authorization": API_KEY
}

# ==========================
# LOGGING SETUP
# ==========================
def get_app_data_folder():
    app_folder = os.path.join(os.getenv("LOCALAPPDATA", ""), "GymBarcodeBridge")
    fallback_folder = os.path.join(tempfile.gettempdir(), "GymBarcodeBridge")

    for folder in (app_folder, fallback_folder):
        if not folder:
            continue
        try:
            os.makedirs(folder, exist_ok=True)
            return folder
        except Exception:
            continue

    return os.getcwd()


def get_config_file_path():
    return os.path.join(get_app_data_folder(), "config.json")


def get_logo_file_path():
    base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    candidates = [
        "logo.png",
        "gym_engine_logo.png",
        "gym-logo.png",
    ]
    for name in candidates:
        candidate = os.path.join(base_dir, name)
        if os.path.exists(candidate):
            return candidate
    return None


def load_config():
    config_path = get_config_file_path()
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_config(config):
    config_path = get_config_file_path()
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def normalize_subdomain(value):
    subdomain = (value or "").strip().lower()
    if re.fullmatch(r"[a-z0-9-]{1,63}", subdomain):
        return subdomain
    return None


def parse_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def encrypt_secret(plain_text):
    value = str(plain_text or "")
    if not value:
        return ""
    if os.name != "nt":
        return value

    try:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char)),
            ]

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        raw = value.encode("utf-8")
        raw_buffer = ctypes.create_string_buffer(raw)
        in_blob = DATA_BLOB(len(raw), ctypes.cast(raw_buffer, ctypes.POINTER(ctypes.c_char)))
        out_blob = DATA_BLOB()

        if not crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            "BarcodeBridgePassword",
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        ):
            return value

        try:
            encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return base64.b64encode(encrypted).decode("ascii")
        finally:
            kernel32.LocalFree(out_blob.pbData)
    except Exception as e:
        logging.warning(f"Password encryption failed: {e}")
        return value


def decrypt_secret(encrypted_value):
    value = str(encrypted_value or "")
    if not value:
        return ""
    if os.name != "nt":
        return value

    try:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char)),
            ]

        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        encrypted_bytes = base64.b64decode(value)
        encrypted_buffer = ctypes.create_string_buffer(encrypted_bytes)
        in_blob = DATA_BLOB(len(encrypted_bytes), ctypes.cast(encrypted_buffer, ctypes.POINTER(ctypes.c_char)))
        out_blob = DATA_BLOB()

        if not crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        ):
            return ""

        try:
            plain = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return plain.decode("utf-8", errors="ignore")
        finally:
            kernel32.LocalFree(out_blob.pbData)
    except Exception:
        return ""


def get_effective_settings():
    raw_config = load_config()
    settings = DEFAULT_APP_SETTINGS.copy()

    for key, default_value in DEFAULT_APP_SETTINGS.items():
        if key in raw_config:
            if isinstance(default_value, bool):
                settings[key] = parse_bool(raw_config.get(key))
            else:
                settings[key] = raw_config.get(key)

    normalized = normalize_subdomain(settings.get("subdomain"))
    settings["subdomain"] = normalized or DEFAULT_SUBDOMAIN

    legacy_plain_password = str(raw_config.get("auth_password") or "")
    encrypted_password = str(raw_config.get("auth_password_enc") or "")
    decrypted_password = decrypt_secret(encrypted_password) if encrypted_password else ""
    settings["auth_password"] = decrypted_password or legacy_plain_password
    settings["auth_phone"] = str(raw_config.get("auth_phone") or settings.get("auth_phone") or "").strip()
    settings["update_manifest_url"] = str(settings.get("update_manifest_url") or "").strip() or DEFAULT_UPDATE_MANIFEST_URL

    return settings


def is_initial_setup_needed(settings):
    return not bool(settings.get("setup_completed"))


def get_log_file_path():
    return os.path.join(get_app_data_folder(), "barcode_scans.log")


logging.basicConfig(
    filename=get_log_file_path(),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ==========================
# INTERNAL STATE
# ==========================
barcode_buffer = ""
last_scan_time = 0
recent_scans = {}  # barcode -> last scan time
running = True  # for tray pause/resume
last_key_time = 0.0
tray_icon = None
app_settings = get_effective_settings()
current_subdomain = app_settings["subdomain"]
enable_employee_attendance = app_settings["enable_employee_attendance"]
enable_client_attendance = app_settings["enable_client_attendance"]
enable_toast = app_settings["enable_toast"]
enable_sound = app_settings["enable_sound"]
enable_auto_update = app_settings.get("enable_auto_update", True)
update_manifest_url = str(app_settings.get("update_manifest_url") or "").strip()
authorized_user = None


def build_api_url(path):
    return f"https://{current_subdomain}.{BASE_DOMAIN}{path}"


def show_settings_screen(initial_settings, startup_mode=False):
    if not tk:
        return initial_settings

    result = {"value": None}
    root = tk.Tk()
    root.title("Barcode Bridge")
    root.geometry("760x700")
    root.minsize(640, 560)
    root.resizable(True, True)

    theme_bg = "#081223"
    theme_surface = "#0f1b33"
    theme_card = "#12213d"
    theme_border = "#1f335a"
    theme_text = "#f8fafc"
    theme_muted = "#cbd5e1"
    theme_gold = "#d4af37"
    theme_red = "#ef3b2d"
    theme_blue = "#93c5fd"

    root.configure(bg=theme_bg)

    shell = tk.Frame(root, bg=theme_bg)
    shell.pack(fill="both", expand=True, padx=16, pady=16)

    canvas = tk.Canvas(shell, bg=theme_bg, bd=0, highlightthickness=0)
    scrollbar = tk.Scrollbar(shell, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    frame = tk.Frame(canvas, bg=theme_surface, bd=0, highlightthickness=1, highlightbackground=theme_border)
    canvas_window = canvas.create_window((0, 0), window=frame, anchor="nw")

    def _on_frame_configure(_event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    def _on_canvas_configure(event):
        canvas.itemconfig(canvas_window, width=event.width)

    frame.bind("<Configure>", _on_frame_configure)
    canvas.bind("<Configure>", _on_canvas_configure)

    logo_photo = None
    logo_path = get_logo_file_path()
    if logo_path and ImageTk:
        try:
            logo_image = Image.open(logo_path).convert("RGBA")
            logo_image.thumbnail((220, 120), Image.Resampling.LANCZOS)
            logo_photo = ImageTk.PhotoImage(logo_image)
            logo_label = tk.Label(frame, image=logo_photo, bg=theme_surface, bd=0)
            logo_label.image = logo_photo
            logo_label.pack(anchor="center", pady=(16, 4))
        except Exception as e:
            logging.warning(f"Could not load logo image: {e}")

    label_title = tk.Label(
        frame,
        text="GYM ENGINE | Barcode Bridge",
        font=("Segoe UI Semibold", 20),
        fg=theme_text,
        bg=theme_surface,
    )
    label_title.pack(anchor="w", pady=(10, 2), padx=24)

    label_subtitle = tk.Label(
        frame,
        text="Smart access setup with secure login, attendance controls, and branded experience",
        font=("Segoe UI", 10),
        fg=theme_gold,
        bg=theme_surface,
    )
    label_subtitle.pack(anchor="w", pady=(0, 14), padx=24)

    top_card = tk.Frame(frame, bg=theme_card, bd=0, highlightthickness=1, highlightbackground=theme_border)
    top_card.pack(fill="x", padx=24, pady=(0, 12))

    label_hint = tk.Label(top_card, text="Subdomain", font=("Segoe UI Semibold", 10), fg=theme_text, bg=theme_card)
    label_hint.pack(anchor="w", pady=(12, 4), padx=14)

    subdomain_var = tk.StringVar(value=initial_settings.get("subdomain") or DEFAULT_SUBDOMAIN)
    entry = tk.Entry(
        top_card,
        textvariable=subdomain_var,
        font=("Segoe UI", 12),
        justify="left",
        relief="flat",
        bd=0,
        fg="#0f172a",
        bg="#f8fafc",
        insertbackground="#0f172a",
    )
    entry.pack(padx=14, fill="x", ipady=9)
    entry.focus_set()
    entry.select_range(0, tk.END)

    preview_var = tk.StringVar()

    def refresh_preview(*_):
        raw = normalize_subdomain(subdomain_var.get()) or subdomain_var.get().strip().lower() or "..."
        preview_var.set(f"https://{raw}.{BASE_DOMAIN}")

    refresh_preview()
    subdomain_var.trace_add("write", refresh_preview)

    preview_label = tk.Label(
        top_card,
        textvariable=preview_var,
        font=("Consolas", 10),
        fg=theme_blue,
        bg=theme_card,
    )
    preview_label.pack(anchor="w", padx=14, pady=(10, 12))

    mid = tk.Frame(frame, bg=theme_surface)
    mid.pack(fill="x", padx=24)
    mid.grid_columnconfigure(0, weight=1, uniform="cols")
    mid.grid_columnconfigure(1, weight=1, uniform="cols")

    auth_card = tk.Frame(mid, bg=theme_card, bd=0, highlightthickness=1, highlightbackground=theme_border)
    auth_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=(0, 0))

    auth_title = tk.Label(
        auth_card,
        text="Bridge Authentication",
        font=("Segoe UI Semibold", 11),
        fg=theme_text,
        bg=theme_card,
    )
    auth_title.pack(anchor="w", padx=12, pady=(10, 8))

    auth_phone_var = tk.StringVar(value=str(initial_settings.get("auth_phone") or ""))
    auth_password_var = tk.StringVar(value=str(initial_settings.get("auth_password") or ""))

    phone_label = tk.Label(auth_card, text="Phone", font=("Segoe UI", 9), fg=theme_muted, bg=theme_card)
    phone_label.pack(anchor="w", padx=12)
    phone_entry = tk.Entry(
        auth_card,
        textvariable=auth_phone_var,
        font=("Segoe UI", 11),
        relief="flat",
        bd=0,
        fg="#0f172a",
        bg="#f8fafc",
        insertbackground="#0f172a",
    )
    phone_entry.pack(fill="x", padx=12, ipady=7, pady=(2, 8))

    password_label = tk.Label(auth_card, text="Password", font=("Segoe UI", 9), fg=theme_muted, bg=theme_card)
    password_label.pack(anchor="w", padx=12)
    password_entry = tk.Entry(
        auth_card,
        textvariable=auth_password_var,
        show="*",
        font=("Segoe UI", 11),
        relief="flat",
        bd=0,
        fg="#0f172a",
        bg="#f8fafc",
        insertbackground="#0f172a",
    )
    password_entry.pack(fill="x", padx=12, ipady=7, pady=(2, 12))

    options_card = tk.Frame(mid, bg=theme_card, bd=0, highlightthickness=1, highlightbackground=theme_border)
    options_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0), pady=(0, 0))

    def update_card_layout(*_):
        width = root.winfo_width()
        if width < 760:
            auth_card.grid_configure(row=0, column=0, padx=0, pady=(0, 10), sticky="nsew")
            options_card.grid_configure(row=1, column=0, padx=0, pady=(0, 0), sticky="nsew")
            mid.grid_columnconfigure(1, weight=0)
        else:
            auth_card.grid_configure(row=0, column=0, padx=(0, 8), pady=0, sticky="nsew")
            options_card.grid_configure(row=0, column=1, padx=(8, 0), pady=0, sticky="nsew")
            mid.grid_columnconfigure(1, weight=1, uniform="cols")

    root.bind("<Configure>", lambda _event: update_card_layout())
    update_card_layout()

    options_title = tk.Label(
        options_card,
        text="Attendance & Notifications",
        font=("Segoe UI Semibold", 11),
        fg=theme_text,
        bg=theme_card,
    )
    options_title.pack(anchor="w", padx=12, pady=(10, 8))

    employee_var = tk.IntVar(value=1 if safe_bool(initial_settings.get("enable_employee_attendance")) else 0)
    client_var = tk.IntVar(value=1 if safe_bool(initial_settings.get("enable_client_attendance")) else 0)
    toast_var = tk.IntVar(value=1 if safe_bool(initial_settings.get("enable_toast")) else 0)
    sound_var = tk.IntVar(value=1 if safe_bool(initial_settings.get("enable_sound")) else 0)
    auto_update_var = tk.IntVar(value=1 if safe_bool(initial_settings.get("enable_auto_update", True)) else 0)
    manifest_url_var = tk.StringVar(value=str(initial_settings.get("update_manifest_url") or ""))

    option_style = {
        "bg": theme_card,
        "fg": "#e5e7eb",
        "selectcolor": theme_card,
        "activebackground": theme_card,
        "activeforeground": "#ffffff",
        "font": ("Segoe UI", 10),
    }

    tk.Checkbutton(options_card, text="Enable Employee Attendance", variable=employee_var, **option_style).pack(anchor="w", padx=12, pady=2)
    tk.Checkbutton(options_card, text="Enable Client Attendance", variable=client_var, **option_style).pack(anchor="w", padx=12, pady=2)
    tk.Checkbutton(options_card, text="Enable Toast Notifications", variable=toast_var, **option_style).pack(anchor="w", padx=12, pady=2)
    tk.Checkbutton(options_card, text="Enable Sounds", variable=sound_var, **option_style).pack(anchor="w", padx=12, pady=(2, 10))
    tk.Checkbutton(options_card, text="Enable Auto Update", variable=auto_update_var, **option_style).pack(anchor="w", padx=12, pady=(2, 10))

    update_card = tk.Frame(frame, bg=theme_card, bd=0, highlightthickness=1, highlightbackground=theme_border)
    update_card.pack(fill="x", padx=24, pady=(12, 0))

    update_title = tk.Label(update_card, text="Updates", font=("Segoe UI Semibold", 11), fg=theme_text, bg=theme_card)
    update_title.pack(anchor="w", padx=12, pady=(10, 6))

    update_hint = tk.Label(
        update_card,
        text="Manifest URL (JSON with version + script_url)",
        font=("Segoe UI", 9),
        fg=theme_muted,
        bg=theme_card,
    )
    update_hint.pack(anchor="w", padx=12, pady=(0, 4))

    manifest_entry = tk.Entry(
        update_card,
        textvariable=manifest_url_var,
        font=("Segoe UI", 10),
        relief="flat",
        bd=0,
        fg="#0f172a",
        bg="#f8fafc",
        insertbackground="#0f172a",
    )
    manifest_entry.pack(fill="x", padx=12, ipady=7, pady=(0, 10))

    status_var = tk.StringVar(value="")

    status_label = tk.Label(
        frame,
        textvariable=status_var,
        font=("Segoe UI", 10),
        fg="#fca5a5",
        bg=theme_surface,
    )
    status_label.pack(anchor="w", padx=24, pady=(10, 0))

    def on_start():
        value = normalize_subdomain(subdomain_var.get())
        if not value:
            if messagebox:
                messagebox.showerror("Invalid subdomain", "Use letters, numbers, or '-' only.")
            return
        if employee_var.get() == 0 and client_var.get() == 0:
            status_var.set("Enable at least one attendance type (Employee or Client).")
            return

        auth_phone = auth_phone_var.get().strip()
        auth_password = auth_password_var.get()
        if not auth_phone or not auth_password:
            status_var.set("Phone and password are required for bridge access.")
            return

        result["value"] = {
            "subdomain": value,
            "auth_phone": auth_phone,
            "auth_password": auth_password,
            "enable_employee_attendance": bool(employee_var.get()),
            "enable_client_attendance": bool(client_var.get()),
            "enable_toast": bool(toast_var.get()),
            "enable_sound": bool(sound_var.get()),
            "enable_auto_update": bool(auto_update_var.get()),
            "update_manifest_url": manifest_url_var.get().strip(),
            "setup_completed": True,
        }
        root.destroy()

    def on_exit():
        root.destroy()

    buttons = tk.Frame(frame, bg=theme_surface)
    buttons.pack(pady=16, padx=24, fill="x")

    start_btn = tk.Button(
        buttons,
        text="Save & Start" if startup_mode else "Save Settings",
        command=on_start,
        bg=theme_red,
        fg="#ffffff",
        activebackground="#dc2626",
        activeforeground="#ffffff",
        relief="flat",
        bd=0,
        padx=22,
        pady=10,
        cursor="hand2",
    )
    start_btn.pack(side=tk.LEFT)

    exit_btn = tk.Button(
        buttons,
        text="Exit" if startup_mode else "Cancel",
        command=on_exit,
        bg="#1f2937",
        fg="#e5e7eb",
        activebackground="#374151",
        activeforeground="#e5e7eb",
        relief="flat",
        bd=0,
        padx=22,
        pady=10,
        cursor="hand2",
    )
    exit_btn.pack(side=tk.LEFT, padx=(10, 0))

    gold_divider = tk.Frame(frame, bg=theme_gold, height=2)
    gold_divider.pack(fill="x", padx=24, pady=(0, 14))

    root.bind("<Return>", lambda _event: on_start())
    root.bind("<Escape>", lambda _event: on_exit())

    root.protocol("WM_DELETE_WINDOW", on_exit)
    root.mainloop()
    return result["value"]


def apply_runtime_settings(settings):
    global app_settings, current_subdomain
    global enable_employee_attendance, enable_client_attendance, enable_toast, enable_sound
    global enable_auto_update, update_manifest_url

    app_settings = get_effective_settings()
    app_settings.update(settings)

    normalized = normalize_subdomain(app_settings.get("subdomain"))
    app_settings["subdomain"] = normalized or DEFAULT_SUBDOMAIN
    app_settings["enable_employee_attendance"] = parse_bool(app_settings.get("enable_employee_attendance"))
    app_settings["enable_client_attendance"] = parse_bool(app_settings.get("enable_client_attendance"))
    app_settings["enable_toast"] = parse_bool(app_settings.get("enable_toast"))
    app_settings["enable_sound"] = parse_bool(app_settings.get("enable_sound"))
    app_settings["setup_completed"] = parse_bool(app_settings.get("setup_completed"))
    app_settings["auth_phone"] = str(app_settings.get("auth_phone") or "").strip()
    app_settings["auth_password"] = str(app_settings.get("auth_password") or "")
    app_settings["enable_auto_update"] = parse_bool(app_settings.get("enable_auto_update"))
    app_settings["update_manifest_url"] = str(app_settings.get("update_manifest_url") or "").strip()

    current_subdomain = app_settings["subdomain"]
    enable_employee_attendance = app_settings["enable_employee_attendance"]
    enable_client_attendance = app_settings["enable_client_attendance"]
    enable_toast = app_settings["enable_toast"]
    enable_sound = app_settings["enable_sound"]
    enable_auto_update = app_settings["enable_auto_update"]
    update_manifest_url = app_settings["update_manifest_url"]


def build_persisted_settings(settings):
    persisted = dict(settings)
    plain_password = str(settings.get("auth_password") or "")
    persisted["auth_password_enc"] = encrypt_secret(plain_password) if plain_password else ""
    persisted.pop("auth_password", None)
    return persisted


def authenticate_bridge_user():
    global authorized_user

    phone = str(app_settings.get("auth_phone") or "").strip()
    password = str(app_settings.get("auth_password") or "")

    if not phone or not password:
        logging.error("Bridge authentication credentials are missing.")
        message = "Missing bridge login credentials in settings"
        send_toast_ar("Barcode Bridge", message)
        return False, message

    def deny_message(data, default_message="Authentication failed"):
        return str(data.get("message") or data.get("error") or default_message)

    def is_allowed_user(user):
        if not isinstance(user, dict):
            return False
        return int(user.get("is_client") or 0) != 1 and int(user.get("is_coach") or 0) != 1

    def login_with_bridge_auth():
        return post_json(build_api_url(API_PATH_AUTH), {
            "phone": phone,
            "password": password,
        })

    def login_with_fallback_auth():
        return post_json(build_api_url(API_PATH_LOGIN_FALLBACK), {
            "phone": phone,
            "password": password,
            "minimal": True,
            "device_name": "Barcode Bridge",
        })

    try:
        data = login_with_bridge_auth()
    except Exception as e:
        logging.error(f"Bridge authentication request failed: {e}")
        message = f"Auth request failed: {e}"
        send_toast_ar("Barcode Bridge", message)
        return False, message

    if str(data.get("status", "")).lower() == "success":
        user = data.get("user") if isinstance(data.get("user"), dict) else {}
        if not is_allowed_user(user):
            message = "غير مصرح. هذه الواجهة متاحة فقط للموظفين والإدارة."
            logging.warning(f"Bridge authentication denied: {message}")
            send_toast_ar("Barcode Bridge", f"Auth denied: {message}")
            return False, message
        authorized_user = user
        logging.info(f"Bridge authenticated user: {user.get('name') or phone}")
        return True, ""

    auth_message = deny_message(data)
    route_missing = (
        "could not be found" in auth_message.lower()
        and "barcode-bridge/auth" in auth_message.lower()
    )

    if route_missing:
        logging.warning("Bridge auth route not found, trying fallback /api/login")
        try:
            fallback_data = login_with_fallback_auth()
        except Exception as e:
            message = f"Fallback auth failed: {e}"
            logging.warning(message)
            send_toast_ar("Barcode Bridge", message)
            return False, message

        user = fallback_data.get("user") if isinstance(fallback_data.get("user"), dict) else None
        if user and fallback_data.get("token"):
            if not is_allowed_user(user):
                message = "غير مصرح. هذه الواجهة متاحة فقط للموظفين والإدارة."
                logging.warning(f"Fallback authentication denied: {message}")
                send_toast_ar("Barcode Bridge", f"Auth denied: {message}")
                return False, message

            authorized_user = user
            logging.info(f"Bridge authenticated via fallback login: {user.get('name') or phone}")
            return True, ""

        message = deny_message(fallback_data, "Fallback authentication failed")
        logging.warning(f"Fallback authentication denied: {message}")
        send_toast_ar("Barcode Bridge", f"Auth denied: {message}")
        return False, message

    message = auth_message
    logging.warning(f"Bridge authentication denied: {message}")
    send_toast_ar("Barcode Bridge", f"Auth denied: {message}")
    return False, str(message)


def parse_version(version_text):
    parts = re.findall(r"\d+", str(version_text or ""))
    if not parts:
        return (0,)
    return tuple(int(part) for part in parts)


def is_newer_version(latest, current):
    return parse_version(latest) > parse_version(current)


def get_installed_version():
    value = str(app_settings.get("installed_version") or "").strip()
    return value or APP_VERSION


def persist_installed_version(version_text):
    version = str(version_text or "").strip()
    if not version:
        return
    app_settings["installed_version"] = version
    config = load_config()
    config.update(build_persisted_settings(app_settings))
    config.pop("auth_password", None)
    try:
        save_config(config)
    except Exception as e:
        logging.warning(f"Failed to persist installed version: {e}")


def check_for_auto_update():
    if not enable_auto_update:
        return False, None, "Auto update disabled"

    manifest_url = str(update_manifest_url or "").strip()
    if not manifest_url:
        return False, None, "No update manifest URL configured"

    try:
        response = requests.get(manifest_url, timeout=UPDATE_CHECK_TIMEOUT)
        response.raise_for_status()
        manifest = response.json() if response.content else {}
        if not isinstance(manifest, dict):
            return False, None, "Invalid update manifest format"
    except Exception as e:
        return False, None, f"Update check failed: {e}"

    latest_version = str(manifest.get("version") or "").strip()
    if not latest_version:
        return False, None, "Manifest missing version"

    if not is_newer_version(latest_version, get_installed_version()):
        return False, None, "No newer version"

    return True, manifest, "Update available"


def resolve_update_artifact(manifest):
    is_frozen = bool(getattr(sys, "frozen", False))

    if is_frozen:
        download_url = str(manifest.get("exe_url") or manifest.get("download_url") or "").strip()
        expected_sha256 = str(manifest.get("exe_sha256") or manifest.get("sha256") or "").strip().lower()
        if not download_url:
            return None, "Manifest missing exe_url for EXE updates"
        return {
            "artifact_type": "exe",
            "download_url": download_url,
            "expected_sha256": expected_sha256,
            "suffix": ".exe",
        }, ""

    download_url = str(manifest.get("script_url") or manifest.get("download_url") or "").strip()
    expected_sha256 = str(manifest.get("script_sha256") or manifest.get("sha256") or "").strip().lower()
    expected_sha256_lf = str(manifest.get("script_sha256_lf") or manifest.get("sha256_lf") or "").strip().lower()
    if not download_url:
        return None, "Manifest missing script_url for script updates"
    return {
        "artifact_type": "script",
        "download_url": download_url,
        "expected_sha256": expected_sha256,
        "expected_sha256_lf": expected_sha256_lf,
        "suffix": ".py",
    }, ""


def download_update_artifact(manifest):
    artifact, error_message = resolve_update_artifact(manifest)
    if not artifact:
        raise ValueError(error_message)

    response = requests.get(artifact["download_url"], timeout=UPDATE_CHECK_TIMEOUT)
    response.raise_for_status()

    update_file = os.path.join(tempfile.gettempdir(), f"barcode_bridge_update_{int(time.time())}{artifact['suffix']}")
    with open(update_file, "wb") as f:
        f.write(response.content)

    expected_sha256 = artifact["expected_sha256"]
    if expected_sha256:
        digest = hashlib.sha256(response.content).hexdigest().lower()
        if digest != expected_sha256:
            lf_hash = str(artifact.get("expected_sha256_lf") or "").strip().lower()
            if artifact.get("artifact_type") == "script" and lf_hash:
                normalized = response.content.replace(b"\r\n", b"\n")
                normalized_digest = hashlib.sha256(normalized).hexdigest().lower()
                if normalized_digest != lf_hash:
                    try:
                        os.remove(update_file)
                    except Exception:
                        pass
                    raise ValueError("Downloaded update hash mismatch")
            else:
                try:
                    os.remove(update_file)
                except Exception:
                    pass
                raise ValueError("Downloaded update hash mismatch")

    artifact["downloaded_file"] = update_file
    return artifact


def apply_update_and_restart(manifest):
    try:
        artifact = download_update_artifact(manifest)
    except Exception as e:
        return False, f"Update download failed: {e}"

    update_file = artifact["downloaded_file"]

    if bool(getattr(sys, "frozen", False)):
        if os.name != "nt":
            return False, "EXE auto-update is supported on Windows only"

        current_exe = os.path.abspath(sys.executable)
        updater_bat = os.path.join(tempfile.gettempdir(), f"barcode_bridge_updater_{int(time.time())}.bat")
        bat = f'''@echo off
ping 127.0.0.1 -n 2 > nul
copy /Y "{update_file}" "{current_exe}" > nul
start "" "{current_exe}"
del /f /q "{update_file}" > nul 2>&1
del /f /q "%~f0"
'''
        with open(updater_bat, "w", encoding="utf-8") as f:
            f.write(bat)

        try:
            subprocess.Popen(["cmd", "/c", updater_bat], creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            subprocess.Popen(["cmd", "/c", updater_bat])
        return True, f"Updated EXE to {manifest.get('version')}"

    current_script = os.path.abspath(sys.argv[0])
    if os.name == "nt":
        launcher = sys.executable
        pythonw_path = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if os.path.exists(pythonw_path):
            launcher = pythonw_path

        updater_bat = os.path.join(tempfile.gettempdir(), f"barcode_bridge_updater_{int(time.time())}.bat")
        bat = f'''@echo off
ping 127.0.0.1 -n 2 > nul
copy /Y "{update_file}" "{current_script}" > nul
start "" "{launcher}" "{current_script}"
del /f /q "{update_file}" > nul 2>&1
del /f /q "%~f0"
'''
        with open(updater_bat, "w", encoding="utf-8") as f:
            f.write(bat)

        try:
            subprocess.Popen(["cmd", "/c", updater_bat], creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            subprocess.Popen(["cmd", "/c", updater_bat])
        return True, f"Updated to {manifest.get('version')}"

    try:
        with open(update_file, "rb") as src, open(current_script, "wb") as dst:
            dst.write(src.read())
        os.remove(update_file)
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        return False, f"Update apply failed: {e}"

    return True, f"Updated to {manifest.get('version')}"


def run_update_check(manual=False):
    update_available, update_manifest, update_message = check_for_auto_update()

    if update_available and update_manifest:
        version = str(update_manifest.get("version") or "new")
        logging.info(f"Auto update available: {version}")
        send_toast_ar("Barcode Bridge", f"Updating to {version}...")
        updated, update_result = apply_update_and_restart(update_manifest)
        if updated:
            persist_installed_version(update_manifest.get("version"))
            logging.info(update_result)
            return True, update_result

        logging.warning(update_result)
        if manual:
            send_toast_ar("Barcode Bridge", update_result)
        return False, update_result

    logging.info(f"Auto update check: {update_message}")
    if manual:
        send_toast_ar("Barcode Bridge", f"Update check: {update_message}")
    return False, update_message


def configure_app_settings(force_prompt=False):
    settings = get_effective_settings()
    selected = settings

    if force_prompt or is_initial_setup_needed(settings):
        selected = show_settings_screen(settings, startup_mode=not force_prompt)

    if not selected:
        return False

    apply_runtime_settings(selected)
    config = load_config()
    config.update(build_persisted_settings(app_settings))
    config.pop("auth_password", None)
    try:
        save_config(config)
    except Exception as e:
        logging.error(f"Failed to save config: {e}")

    return True

# ==========================
# FUNCTIONS
# ==========================
def play_sound(file):
    if not enable_sound:
        return

    if playsound and os.path.exists(file):
        threading.Thread(target=playsound, args=(file,), daemon=True).start()
        return

    if winsound and os.path.exists(file):
        winsound.PlaySound(file, winsound.SND_FILENAME | winsound.SND_ASYNC)
        return

    if winsound:
        winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)


def safe_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

def valid_barcode(barcode):
    """Only allow digits and uppercase letters, length 4-20"""
    return bool(re.fullmatch(r"[A-Z0-9]{4,20}", barcode))


def send_toast_ar(title, message):
    """Show Windows toast notification with robust fallbacks (safe for EXE)."""
    if not enable_toast:
        logging.info(f"TOAST_DISABLED | {title} | {message}")
        return

    if notification:
        try:
            notification.notify(
                title=title,
                message=message,
                timeout=5
            )
            return
        except Exception as e:
            logging.warning(f"Plyer notification failed, using fallback: {e}")

    if send_windows_toast_powershell(title, message):
        return

    global tray_icon
    if tray_icon:
        try:
            tray_icon.notify(message, title)
            return
        except Exception as e:
            logging.warning(f"Tray notification fallback failed: {e}")

    logging.info(f"NOTIFICATION | {title} | {message}")


def send_windows_toast_powershell(title, message):
    if os.name != "nt":
        return False

    safe_title = (title or "").replace("'", "''")
    safe_message = (message or "").replace("'", "''")

    ps_script = f"""
$ErrorActionPreference='Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$t = '{safe_title}'
$m = '{safe_message}'
$template = "<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$m</text></binding></visual></toast>"
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('BarcodeBridge')
$notifier.Show($toast)
"""

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            return True

        logging.warning(f"PowerShell toast failed: {result.stderr.strip() or result.stdout.strip()}")
        return False
    except Exception as e:
        logging.warning(f"PowerShell toast execution error: {e}")
        return False


def hide_console_window():
    if os.name != "nt" or not RUN_IN_BACKGROUND:
        return
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception as e:
        logging.debug(f"Could not hide console window: {e}")


def startup_command():
    script_path = os.path.abspath(sys.argv[0])
    pythonw_path = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    launcher = pythonw_path if os.path.exists(pythonw_path) else sys.executable
    return f'"{launcher}" "{script_path}"'


def is_user_admin():
    if os.name != "nt":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    if os.name != "nt":
        return False

    try:
        import ctypes
        executable = sys.executable
        args = " ".join(f'"{arg}"' for arg in sys.argv)
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, args, None, 1)
        return result > 32
    except Exception as e:
        logging.error(f"Failed to relaunch as admin: {e}")
        return False


def ensure_admin_or_exit():
    if not REQUIRE_ADMIN or os.name != "nt":
        return True
    if is_user_admin():
        return True
    if relaunch_as_admin():
        sys.exit(0)

    logging.error("Administrator privileges are required but elevation was denied.")
    return False


def is_startup_enabled():
    if os.name != "nt":
        return False

    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", STARTUP_TASK_NAME],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            return True
    except Exception as e:
        logging.error(f"Failed to query startup task: {e}")

    if not winreg:
        return False

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
            value, _ = winreg.QueryValueEx(key, STARTUP_VALUE_NAME)
            return bool(value)
    except FileNotFoundError:
        return False
    except Exception as e:
        logging.error(f"Failed to read startup key: {e}")
        return False


def set_startup_enabled(enabled):
    if os.name != "nt":
        return False

    try:
        if enabled:
            command = startup_command()
            result = subprocess.run(
                [
                    "schtasks",
                    "/Create",
                    "/TN",
                    STARTUP_TASK_NAME,
                    "/SC",
                    "ONLOGON",
                    "/RL",
                    "HIGHEST",
                    "/F",
                    "/TR",
                    command,
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                logging.error(f"Failed to create startup task: {result.stderr.strip() or result.stdout.strip()}")
                return False
        else:
            subprocess.run(
                ["schtasks", "/Delete", "/TN", STARTUP_TASK_NAME, "/F"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        if winreg:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0,
                    winreg.KEY_SET_VALUE,
                ) as key:
                    try:
                        winreg.DeleteValue(key, STARTUP_VALUE_NAME)
                    except FileNotFoundError:
                        pass
            except Exception as e:
                logging.warning(f"Could not clean legacy startup registry key: {e}")

        return True
    except Exception as e:
        logging.error(f"Failed to set startup key: {e}")
        return False


def update_tray_status():
    global tray_icon
    if tray_icon:
        tray_icon.icon = create_image()
        tray_icon.title = "Barcode Bridge - Running" if running else "Barcode Bridge - Paused"


def post_json(url, payload):
    response = requests.post(url, json=payload, headers=HEADERS, timeout=REQUEST_TIMEOUT)
    try:
        data = response.json()
        if not isinstance(data, dict):
            data = {}
    except ValueError:
        data = {}

    if response.status_code != 200:
        data.setdefault("status", "error")
        data.setdefault("message", f"HTTP {response.status_code}")

    return data


def is_employee_not_found(message):
    msg = (message or "").lower()
    return (
        "not found" in msg
        or "not registered as an employee" in msg
        or "لم يتم العثور" in msg
    )


def classify_toast_type(data):
    status = str(data.get("status", "")).lower()
    has_remaining_payment = safe_bool(data.get("has_remaining_payment"))
    subscription_about_to_expire = safe_bool(data.get("subscription_about_to_expire"))

    if status == "error":
        return "error"
    if status == "success" and not (has_remaining_payment or subscription_about_to_expire):
        return "success"
    return "warning"


def build_toast_title(data, is_employee):
    toast_type = classify_toast_type(data)

    if not is_employee and safe_bool(data.get("is_birthday")) and toast_type != "error":
        return "عيد ميلاد سعيد 🎂"

    if is_employee:
        if toast_type == "success":
            return "حضور الموظف ✅"
        if toast_type == "error":
            return "حضور الموظف ❌"
        return "حضور الموظف ⚠️"

    if toast_type == "success":
        return "حضور العميل ✅"
    if toast_type == "error":
        return "حضور العميل ❌"
    return "حضور العميل ⚠️"


def build_toast_message(data, is_employee, barcode):
    name = data.get("name") or data.get("user") or "غير معروف"
    user_id = data.get("user_id") or data.get("employee_id") or barcode
    message = data.get("message") or ("تم تسجيل الحضور" if str(data.get("status", "")).lower() == "success" else "غير معروف")

    lines = [
        f"الرسالة: {message}",
        f"الاسم: {name}",
        f"الرقم: {user_id}",
        f"الباركود: {barcode}",
    ]

    if is_employee:
        lines.append(f"المنصب: {data.get('position') or 'N/A'}")
        if data.get("check_in"):
            check_out = data.get("check_out")
            time_line = f"الحضور: {data.get('check_in')}"
            if check_out:
                time_line += f" | الانصراف: {check_out}"
            lines.append(time_line)

        schedule = data.get("schedule_time")
        if isinstance(schedule, dict):
            start = schedule.get("start") or "-"
            end = schedule.get("end") or "-"
            lines.append(f"الجدول: {start} - {end}")
    else:
        lines.append(f"الباقة: {data.get('package') or 'N/A'}")

        if data.get("start_date") and data.get("end_date"):
            lines.append(f"الاشتراك: {data.get('start_date')} → {data.get('end_date')}")

        if safe_bool(data.get("has_remaining_payment")):
            lines.append(f"مبلغ متبقي: {data.get('remaining_amount') or 'يوجد مبلغ متبقي'}")

        if safe_bool(data.get("subscription_about_to_expire")):
            days_until_expiry = safe_int(data.get("days_until_expiry"))
            if days_until_expiry is not None:
                lines.append(f"قرب انتهاء الاشتراك: {days_until_expiry} يوم")
            else:
                lines.append("قرب انتهاء الاشتراك")

        if safe_bool(data.get("is_birthday")):
            lines.append("🎉 اليوم عيد ميلاد العميل")

    return "\n".join(lines)


def notify_scan_result(data, is_employee, barcode):
    title = build_toast_title(data, is_employee)
    message = build_toast_message(data, is_employee, barcode)
    send_toast_ar(title, message)


def play_sound_for_result(data):
    toast_type = classify_toast_type(data)
    if toast_type == "success":
        play_sound(SUCCESS_SOUND)
    elif toast_type == "error":
        play_sound(ERROR_SOUND)

def send_barcode(barcode):
    global last_scan_time, recent_scans

    current_time = time.time()
    if current_time - last_scan_time < DEBOUNCE_TIME:
        logging.info(f"Skipping duplicate scan: {barcode}")
        return
    if barcode in recent_scans and current_time - recent_scans[barcode] < FREEZE_COOLDOWN:
        logging.info(f"Barcode frozen: {barcode}")
        return
    last_scan_time = current_time

    if not valid_barcode(barcode):
        logging.warning(f"Invalid barcode ignored: {barcode}")
        play_sound(ERROR_SOUND)
        send_toast_ar("باركود غير صالح ❌", f"الباركود: {barcode}\nالحالة: غير صالح")
        return

    payload = {"barcode": barcode}

    if not enable_employee_attendance and not enable_client_attendance:
        logging.warning("Both employee and client attendance are disabled.")
        send_toast_ar("Barcode Bridge", "Employee and Client attendance are disabled in settings")
        return

    # 1️⃣ Employee Attendance
    if enable_employee_attendance:
        try:
            data = post_json(build_api_url(API_PATH_EMPLOYEE), payload)
            if data.get("status") == "success":
                logging.info(f"Employee attendance recorded: {barcode}")
                notify_scan_result(data, is_employee=True, barcode=barcode)
                play_sound_for_result(data)
                recent_scans[barcode] = current_time
                return

            if is_employee_not_found(data.get("message")):
                logging.info(f"Employee not found: {barcode}")
            else:
                logging.warning(f"Employee scan failed: {data}")
                notify_scan_result(data, is_employee=True, barcode=barcode)
                play_sound_for_result(data)
                recent_scans[barcode] = current_time
                return
        except Exception as e:
            logging.error(f"Employee scan request failed: {e}")
            send_toast_ar("حضور الموظف ❌", f"الباركود: {barcode}\nالخطأ: {e}")
            play_sound(ERROR_SOUND)
            recent_scans[barcode] = current_time
            return
    else:
        logging.info("Employee attendance is disabled in settings.")

    # 2️⃣ Client Attendance
    if not enable_client_attendance:
        logging.info("Client attendance is disabled in settings.")
        send_toast_ar("Barcode Bridge", "Client attendance is disabled")
        return

    try:
        data = post_json(build_api_url(API_PATH_CLIENT), payload)
        if data.get("status") == "success":
            logging.info(f"Client attendance recorded: {barcode}")
        else:
            logging.warning(f"Client scan failed: {data}")

        notify_scan_result(data, is_employee=False, barcode=barcode)
        play_sound_for_result(data)
        recent_scans[barcode] = current_time
    except Exception as e:
        logging.error(f"Client scan request failed: {e}")
        send_toast_ar("حضور العميل ❌", f"الباركود: {barcode}\nالخطأ: {e}")
        play_sound(ERROR_SOUND)
        recent_scans[barcode] = current_time

# ==========================
# BARCODE LISTENER
# ==========================
def barcode_listener():
    global barcode_buffer, running, last_key_time
    print("[INFO] Barcode bridge running... Press ESC to exit.")
    send_toast_ar("Barcode Bridge 🏋️‍♂️", "تشغيل النظام وجاهز لمسح الباركود...")
    while True:
        if not running:
            time.sleep(0.1)
            continue
        event = keyboard.read_event()
        if event.event_type == keyboard.KEY_DOWN:
            key = event.name
            if key == "esc":
                print("[INFO] Exiting barcode bridge.")
                send_toast_ar("Barcode Bridge ❌", "تم إيقاف البرنامج")
                os._exit(0)
            if key == BARCODE_DELIMITER:
                barcode = barcode_buffer.strip().upper()
                if len(barcode) >= MIN_BARCODE_LENGTH:
                    send_barcode(barcode)
                barcode_buffer = ""
                last_key_time = 0.0
            else:
                if len(key) == 1 and key.isalnum():
                    now = time.time()
                    if last_key_time and (now - last_key_time) > MAX_KEY_INTERVAL:
                        barcode_buffer = ""
                    barcode_buffer += key.upper()
                    last_key_time = now

# ==========================
# SYSTEM TRAY ICON
# ==========================
def create_image():
    """Create tray icon based on scanning status"""
    is_active = running
    img = Image.new('RGB', (64, 64), color=(46, 50, 56))
    d = ImageDraw.Draw(img)
    indicator_color = (46, 204, 113) if is_active else (127, 140, 141)
    d.ellipse((6, 6, 58, 58), fill=indicator_color)
    d.text((16, 20), "BC", fill=(255, 255, 255))
    return img


def on_toggle_startup(icon, item):
    currently_enabled = is_startup_enabled()
    updated = set_startup_enabled(not currently_enabled)
    if updated:
        if not currently_enabled:
            send_toast_ar("Barcode Bridge", "تم تفعيل التشغيل التلقائي مع بدء ويندوز")
        else:
            send_toast_ar("Barcode Bridge", "تم إلغاء التشغيل التلقائي مع بدء ويندوز")
    else:
        send_toast_ar("Barcode Bridge", "تعذر تحديث إعداد التشغيل التلقائي")

def on_quit(icon, item):
    print("[INFO] Exiting from tray menu.")
    os._exit(0)

def on_pause(icon, item):
    global running
    running = not running
    status = "Resumed" if running else "Paused"
    print(f"[INFO] {status} barcode scanning.")
    send_toast_ar(f"Barcode Bridge {status}", f"Scanning {status}")
    update_tray_status()


def on_open_settings(icon, item):
    previous = app_settings.copy()
    if configure_app_settings(force_prompt=True):
        if previous != app_settings:
            send_toast_ar("Barcode Bridge", f"Settings saved\nDomain: {current_subdomain}.{BASE_DOMAIN}")
    else:
        send_toast_ar("Barcode Bridge", "Settings update cancelled")


def on_check_updates(icon, item):
    updated, _ = run_update_check(manual=True)
    if updated:
        os._exit(0)


def startup_checked(item):
    return is_startup_enabled()


def paused_checked(item):
    return not running

def run_tray():
    global tray_icon
    tray_icon = pystray.Icon("barcode_bridge", create_image(), "Barcode Bridge - Running",
                        menu=pystray.Menu(
                            pystray.MenuItem("Settings", on_open_settings),
                            pystray.MenuItem("Check for updates now", on_check_updates),
                            pystray.MenuItem("Paused", on_pause, checked=paused_checked),
                            pystray.MenuItem("Run on Windows startup", on_toggle_startup, checked=startup_checked),
                            pystray.MenuItem("Exit", on_quit)
                        ))
    tray_icon.run()

# ==========================
# MAIN
# ==========================
if __name__ == "__main__":
    if not ensure_admin_or_exit():
        sys.exit(1)

    if not configure_app_settings(force_prompt=False):
        sys.exit(0)

    while True:
        auth_ok, auth_message = authenticate_bridge_user()
        if auth_ok:
            break

        if tk and messagebox:
            retry = messagebox.askretrycancel(
                "Barcode Bridge Authentication",
                f"Authentication failed:\n{auth_message}\n\nRetry after updating settings?",
            )
            if not retry:
                sys.exit(1)
            if not configure_app_settings(force_prompt=True):
                sys.exit(1)
        else:
            sys.exit(1)

    updated, _ = run_update_check(manual=False)
    if updated:
        sys.exit(0)

    hide_console_window()
    if AUTO_ENABLE_STARTUP and not is_startup_enabled():
        if set_startup_enabled(True):
            send_toast_ar("Barcode Bridge", "Startup task created with admin privileges")
    if SHOW_STARTUP_TOAST:
        send_toast_ar("Barcode Bridge 🏋️‍♂️", f"{current_subdomain}.{BASE_DOMAIN}\nيعمل في الخلفية وجاهز لمسح الباركود")
    threading.Thread(target=barcode_listener, daemon=True).start()
    run_tray()
