import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter.font as tkfont
from tkinter import simpledialog, messagebox, filedialog
import subprocess
import os
import json
import keyring

# === CONFIG ===
VNC_VIEWER_PATH = r"C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe"
DATA_FILE = "machines.json"
CONFIG_FILE = "config.json"
KEYRING_SERVICE = "UltraVNCDashboard"

# === Load/Save Config ===
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {"vnc_path": VNC_VIEWER_PATH}

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

# === Check and configure VNC path ===
def check_vnc_path():
    config = load_config()
    vnc_path = config.get("vnc_path", VNC_VIEWER_PATH)
    
    if not os.path.exists(vnc_path):
        messagebox.showwarning("VNC Viewer Not Found", 
                             f"UltraVNC viewer not found at:\n{vnc_path}\n\nPlease locate the vncviewer.exe file.")
        
        new_path = filedialog.askopenfilename(
            title="Select VNC Viewer Executable",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")],
            initialfile="vncviewer.exe"
        )
        
        if new_path and os.path.exists(new_path):
            config["vnc_path"] = new_path
            save_config(config)
            return new_path
        else:
            messagebox.showerror("Error", "Invalid path selected. Application may not function correctly.")
            return None
    
    return vnc_path

# === Load machine list ===
def load_machines():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# === Save machine list ===
def save_machines():
    with open(DATA_FILE, "w") as f:
        json.dump(machines, f, indent=4)

# === Launch VNC viewer ===
def launch_vnc(ip_address, password=None, secure=False):
    config = load_config()
    vnc_path = config.get("vnc_path", VNC_VIEWER_PATH)
    
    if not os.path.exists(vnc_path):
        vnc_path = check_vnc_path()
        if not vnc_path:
            return

    try:
        args = [vnc_path, ip_address, "-viewonly", "-autoscaling"]
        if password:
            args += ["-password", password]
        # Remove the problematic plugin argument - UltraVNC handles encryption automatically
        
        subprocess.Popen(args)
        security_status = "secured" if secure else "unsecured"
        status_var.set(f"Launched VNC for {ip_address} ({security_status})")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start VNC: {e}")
        status_var.set(f"Failed to launch VNC: {e}")

# === Add new machine ===
def add_machine():
    name = simpledialog.askstring("Add Machine", "Enter machine name:")
    if not name:
        return
    ip = simpledialog.askstring("Add Machine", "Enter IP address or hostname:")
    if not ip:
        return

    save_pw = messagebox.askyesno("Store Password?", "Would you like to store a password for this machine?")
    if save_pw:
        password = simpledialog.askstring("Password", f"Enter VNC password for {name}:", show='*')
        if password:
            password = password[:8]
            keyring.set_password(KEYRING_SERVICE, name, password)

    # Ask about security preference
    secure = messagebox.askyesno("Security Setting", 
                                f"Should connections to {name} be secured?\n\n"
                                "Yes = Encrypted connection\n"
                                "No = Unencrypted connection")

    machines[name] = {"ip": ip, "secure": secure}
    save_machines()
    refresh_machine_list()
    status_var.set(f"Added machine: {name}")

# === Remove selected machine ===
def remove_machine():
    name = machine_var.get()
    if not name:
        messagebox.showinfo("No selection", "Please select a machine to remove.")
        return

    if name in machines:
        confirm = messagebox.askyesno("Confirm", f"Remove machine '{name}'?")
        if confirm:
            del machines[name]
            try:
                keyring.delete_password(KEYRING_SERVICE, name)
            except keyring.errors.PasswordDeleteError:
                pass
            save_machines()
            refresh_machine_list()
            status_var.set(f"Removed machine: {name}")

def edit_machine():
    name = machine_var.get()
    if not name:
        messagebox.showinfo("No selection", "Please select a machine to edit.")
        return

    machine_info = machines.get(name, {})
    # Handle old format (string) vs new format (dict)
    if isinstance(machine_info, str):
        current_ip = machine_info
        current_secure = False
    else:
        current_ip = machine_info.get("ip", "")
        current_secure = machine_info.get("secure", False)
    
    new_name = simpledialog.askstring("Edit Machine", "Edit machine name:", initialvalue=name)
    if not new_name:
        return

    new_ip = simpledialog.askstring("Edit Machine", "Edit IP/hostname:", initialvalue=current_ip)
    if not new_ip:
        return

    # Ask about security preference
    secure = messagebox.askyesno("Security Setting", 
                                f"Should connections to {new_name} be secured?\n\n"
                                "Yes = Encrypted connection\n"
                                "No = Unencrypted connection",
                                default=messagebox.YES if current_secure else messagebox.NO)

    change_pw = messagebox.askyesno("Change Password?", f"Change stored password for {new_name}?")
    if change_pw:
        password = simpledialog.askstring("Password", f"Enter new password for {new_name}:", show='*')
        if password:
            password = password[:8]
            keyring.set_password(KEYRING_SERVICE, new_name, password)

    if new_name != name:
        try:
            old_pw = keyring.get_password(KEYRING_SERVICE, name)
            if old_pw:
                keyring.set_password(KEYRING_SERVICE, new_name, old_pw)
                keyring.delete_password(KEYRING_SERVICE, name)
        except Exception:
            pass
        del machines[name]

    machines[new_name] = {"ip": new_ip, "secure": secure}
    save_machines()
    refresh_machine_list()
    status_var.set(f"Edited machine: {new_name}")

# === Refresh machine list ===
def refresh_machine_list(search_query=""):
    for widget in frame_buttons.winfo_children():
        widget.destroy()
    machine_var.set("")
    
    # Filter machines based on search query
    filtered_machines = {
        name: info for name, info in machines.items()
        if search_query.lower() in name.lower() or 
        (isinstance(info, str) and search_query.lower() in info.lower()) or
        (isinstance(info, dict) and search_query.lower() in info.get("ip", "").lower())
    }
    
    # === Find the longest text to determine consistent width ===
    max_width = 0
    if filtered_machines:
        for name, machine_info in filtered_machines.items():
            if isinstance(machine_info, str):
                ip = machine_info
                secure = False
            else:
                ip = machine_info.get("ip", "")
                secure = machine_info.get("secure", False)
            
            security_icon = "🔒" if secure else "🔓"
            text_length = len(f"{security_icon} {name} ({ip})")
            max_width = max(max_width, text_length)
    
    for name, machine_info in filtered_machines.items():
        if isinstance(machine_info, str):
            ip = machine_info
            secure = False
        else:
            ip = machine_info.get("ip", "")
            secure = machine_info.get("secure", False)
        
        security_icon = "🔒" if secure else "🔓"
        
        # === Create radio button with consistent width ===
        radio_btn = ttk.Radiobutton(
            frame_buttons,
            text=f"{security_icon} {name} ({ip})",
            variable=machine_var,
            value=name,
            bootstyle="info",
            width=max_width
        )
        radio_btn.pack(pady=5, anchor="center")
    
    # === Update the canvas scroll region ===
    frame_buttons.update_idletasks()
    canvas.configure(scrollregion=canvas.bbox("all"))

# === Launch selected ===
def launch_selected_machine():
    name = machine_var.get()
    if not name:
        messagebox.showwarning("No Selection", "Please select a machine.")
        return

    machine_info = machines.get(name, {})
    # Handle old format (string) vs new format (dict)
    if isinstance(machine_info, str):
        ip = machine_info
        secure = False
    else:
        ip = machine_info.get("ip", "")
        secure = machine_info.get("secure", False)
    
    password = keyring.get_password(KEYRING_SERVICE, name)
    # Connect directly without confirmation
    launch_vnc(ip, password, secure)

# === GUI Setup ===
root = ttk.Window(themename="flatly")
root.title("UltraVNC Dashboard")
root.geometry("500x600")

default_font = tkfont.nametofont("TkDefaultFont")
default_font.configure(family="Segoe UI", size=12)

text_font = tkfont.nametofont("TkTextFont")
text_font.configure(family="Segoe UI", size=12)

fixed_font = tkfont.nametofont("TkFixedFont")
fixed_font.configure(family="Courier New", size=12)

machines = load_machines()
machine_var = ttk.StringVar()

# Check VNC path on startup
check_vnc_path()

# === Title ===
frame_top = ttk.Frame(root)
frame_top.pack(pady=10)
ttk.Label(frame_top, text="VNC Dashboard", font=("Segoe UI", 16, "bold")).pack()

# === Search Bar ===
frame_search = ttk.Frame(root)
frame_search.pack(pady=5, fill="x", padx=10)
search_var = ttk.StringVar()
# === Bind KeyRelease to update the machine list as the user types ===
search_var.trace_add("write", lambda *args: refresh_machine_list(search_var.get()))
ttk.Entry(frame_search, textvariable=search_var, bootstyle="info").pack(fill="x")
ttk.Label(frame_search, text="Search machines by name or IP").pack()
# === Added: Clear button for search bar ===
ttk.Button(frame_search, text="Clear", command=lambda: search_var.set(""), bootstyle="secondary").pack(side="right", padx=5)


# === Scrollable Machine List ===
frame_buttons_container = ttk.Frame(root)
frame_buttons_container.pack(pady=10, fill="both", expand=True)

canvas = tk.Canvas(frame_buttons_container)
scrollbar = ttk.Scrollbar(frame_buttons_container, orient="vertical", command=canvas.yview)
scrollable_frame = ttk.Frame(canvas)

scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
)

canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

# === Configure the canvas window to expand with the canvas width ===
def configure_canvas_width(event):
    canvas.itemconfig(canvas.find_all()[0], width=event.width)

canvas.bind('<Configure>', configure_canvas_width)

# === Add Mouse Wheel Scrolling for Windows ===
def on_mouse_wheel(event):
    # Scroll the canvas based on mouse wheel movement
    # delta is positive for scroll up, negative for scroll down
    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

# === Bind mouse wheel to the canvas (Windows uses <MouseWheel>) ===
canvas.bind("<MouseWheel>", on_mouse_wheel)

# Bind mouse wheel to the scrollable frame and its children
def bind_mouse_wheel(widget):
    widget.bind("<MouseWheel>", on_mouse_wheel)
    for child in widget.winfo_children():
        bind_mouse_wheel(child)

# === Apply bindings to the scrollable frame and its children ===
bind_mouse_wheel(scrollable_frame)

# === Ensure the canvas can receive focus to capture mouse wheel events ===
canvas.bind("<Button-1>", lambda event: canvas.focus_set())

canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

frame_buttons = scrollable_frame

# === Actions ===
frame_actions = ttk.Frame(root)
frame_actions.pack(pady=10, fill="x", padx=10)

frame_actions.grid_columnconfigure(0, weight=1)
frame_actions.grid_columnconfigure(1, weight=1)
frame_actions.grid_columnconfigure(2, weight=1)
frame_actions.grid_columnconfigure(3, weight=1)

# === Status Bar ===
status_var = ttk.StringVar()
ttk.Label(root, textvariable=status_var, anchor="w", relief="sunken", bootstyle="secondary").pack(fill="x", side="bottom")
status_var.set("Ready")

# === Configure columns to expand equally ===
frame_actions.grid_columnconfigure(0, weight=1)
frame_actions.grid_columnconfigure(1, weight=1)
frame_actions.grid_columnconfigure(2, weight=1)
frame_actions.grid_columnconfigure(3, weight=1)

ttk.Button(frame_actions, text="Launch", command=launch_selected_machine, bootstyle="success").grid(row=0, column=0, sticky="ew", padx=2)
ttk.Button(frame_actions, text=" Add  ", command=add_machine, bootstyle="primary").grid(row=0, column=1, sticky="ew", padx=2)
ttk.Button(frame_actions, text=" Edit ", command=edit_machine, bootstyle="warning").grid(row=0, column=2, sticky="ew", padx=2)
ttk.Button(frame_actions, text="Remove", command=remove_machine, bootstyle="danger").grid(row=0, column=3, sticky="ew", padx=2)

refresh_machine_list()
root.mainloop()