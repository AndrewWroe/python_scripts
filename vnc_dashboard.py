import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter.font as tkfont
from tkinter import simpledialog, messagebox, filedialog
import subprocess
import os
import json
import keyring
import base64
from datetime import datetime

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

# === Import/Export Functions ===
def export_config():
    """Export machines configuration and passwords to a JSON file"""
    try:
        # Gather all machine data
        export_data = {
            "metadata": {
                "export_date": datetime.now().isoformat(),
                "app_version": "1.0",
                "description": "UltraVNC Dashboard Export"
            },
            "config": load_config(),
            "machines": {},
            "passwords": {}
        }
        
        # Export machine configurations
        for name, machine_info in machines.items():
            export_data["machines"][name] = machine_info
            
            # Export passwords (encoded for basic security)
            try:
                password = keyring.get_password(KEYRING_SERVICE, name)
                if password:
                    # Base64 encode for basic obfuscation (not real security)
                    encoded_password = base64.b64encode(password.encode()).decode()
                    export_data["passwords"][name] = encoded_password
            except Exception:
                pass
        
        # Ask user for export location
        file_path = filedialog.asksaveasfilename(
            title="Export Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"vnc_config_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if file_path:
            with open(file_path, "w") as f:
                json.dump(export_data, f, indent=4)
            
            machine_count = len(export_data["machines"])
            password_count = len(export_data["passwords"])
            
            messagebox.showinfo(
                "Export Successful", 
                f"Configuration exported successfully!\n\n"
                f"Machines: {machine_count}\n"
                f"Passwords: {password_count}\n"
                f"File: {file_path}"
            )
            status_var.set(f"Exported {machine_count} machines to {os.path.basename(file_path)}")
        
    except Exception as e:
        messagebox.showerror("Export Error", f"Failed to export configuration:\n{str(e)}")
        status_var.set("Export failed")

def import_config():
    """Import machines configuration and passwords from a JSON file"""
    try:
        # Ask user for import file
        file_path = filedialog.askopenfilename(
            title="Import Configuration",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        with open(file_path, "r") as f:
            import_data = json.load(f)
        
        # Validate import data structure
        if not isinstance(import_data, dict) or "machines" not in import_data:
            messagebox.showerror("Import Error", "Invalid configuration file format.")
            return
        
        # Show import preview
        machine_count = len(import_data.get("machines", {}))
        password_count = len(import_data.get("passwords", {}))
        export_date = import_data.get("metadata", {}).get("export_date", "Unknown")
        
        confirm_msg = (
            f"Import Configuration Preview:\n\n"
            f"Machines to import: {machine_count}\n"
            f"Passwords to import: {password_count}\n"
            f"Export date: {export_date}\n\n"
            f"Choose import mode:"
        )
        
        # Ask for import mode
        import_mode = messagebox.askyesnocancel(
            "Import Mode", 
            confirm_msg + "\n\nYes = Merge (keep existing)\nNo = Replace (overwrite all)\nCancel = Abort"
        )
        
        if import_mode is None:  # User cancelled
            return
        
        imported_machines = 0
        imported_passwords = 0
        skipped_machines = 0
        
        # Import machines
        for name, machine_info in import_data.get("machines", {}).items():
            if import_mode and name in machines:  # Merge mode and machine exists
                skip = not messagebox.askyesno(
                    "Duplicate Machine", 
                    f"Machine '{name}' already exists. Overwrite?"
                )
                if skip:
                    skipped_machines += 1
                    continue
            
            machines[name] = machine_info
            imported_machines += 1
        
        # Import passwords
        for name, encoded_password in import_data.get("passwords", {}).items():
            if name in machines:  # Only import password if machine exists
                try:
                    # Decode password
                    password = base64.b64decode(encoded_password.encode()).decode()
                    keyring.set_password(KEYRING_SERVICE, name, password)
                    imported_passwords += 1
                except Exception:
                    pass
        
        # Import config settings
        if "config" in import_data:
            current_config = load_config()
            imported_config = import_data["config"]
            
            # Only update VNC path if it's different and valid
            if imported_config.get("vnc_path") != current_config.get("vnc_path"):
                if messagebox.askyesno(
                    "Import VNC Path", 
                    f"Import VNC viewer path?\n\nCurrent: {current_config.get('vnc_path', 'Not set')}\n"
                    f"Import: {imported_config.get('vnc_path', 'Not set')}"
                ):
                    current_config.update(imported_config)
                    save_config(current_config)
        
        # Save changes
        save_machines()
        refresh_machine_list()
        
        # Show results
        result_msg = (
            f"Import completed!\n\n"
            f"Machines imported: {imported_machines}\n"
            f"Passwords imported: {imported_passwords}\n"
            f"Machines skipped: {skipped_machines}"
        )
        
        messagebox.showinfo("Import Successful", result_msg)
        status_var.set(f"Imported {imported_machines} machines from {os.path.basename(file_path)}")
        
    except Exception as e:
        messagebox.showerror("Import Error", f"Failed to import configuration:\n{str(e)}")
        status_var.set("Import failed")

def backup_current_config():
    """Create a backup of current configuration"""
    try:
        backup_dir = "backups"
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        backup_filename = f"vnc_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Use export function to create backup
        export_data = {
            "metadata": {
                "export_date": datetime.now().isoformat(),
                "app_version": "1.0",
                "description": "Automatic Backup"
            },
            "config": load_config(),
            "machines": machines.copy(),
            "passwords": {}
        }
        
        # Backup passwords
        for name in machines.keys():
            try:
                password = keyring.get_password(KEYRING_SERVICE, name)
                if password:
                    encoded_password = base64.b64encode(password.encode()).decode()
                    export_data["passwords"][name] = encoded_password
            except Exception:
                pass
        
        with open(backup_path, "w") as f:
            json.dump(export_data, f, indent=4)
        
        return backup_path
        
    except Exception as e:
        messagebox.showerror("Backup Error", f"Failed to create backup:\n{str(e)}")
        return None

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
        if secure:
            args = [vnc_path, ip_address, "-viewonly", "-autoscaling", "-dsmplugin", "SecureVNCPlugin64.dsm"]
        else:
            args = [vnc_path, ip_address, "-viewonly", "-autoscaling"]
        if password:
            args += ["-password", password]
        
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
    
    # Sort machines alphabetically by name
    sorted_machines = sorted(filtered_machines.items(), key=lambda x: x[0].lower())
    
    for name, machine_info in sorted_machines:
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
        
        # === Add double-click functionality to launch VNC ===
        def make_launch_handler(machine_name):
            def launch_machine(event=None):
                machine_info = machines.get(machine_name, {})
                if isinstance(machine_info, str):
                    ip = machine_info
                    secure = False
                else:
                    ip = machine_info.get("ip", "")
                    secure = machine_info.get("secure", False)
                
                password = keyring.get_password(KEYRING_SERVICE, machine_name)
                launch_vnc(ip, password, secure)
            return launch_machine
        
        radio_btn.bind("<Double-Button-1>", make_launch_handler(name))
    
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
root.geometry("500x650")  # Made slightly taller for new buttons

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

# === Configure columns to expand equally ===
frame_actions.grid_columnconfigure(0, weight=1)
frame_actions.grid_columnconfigure(1, weight=1)
frame_actions.grid_columnconfigure(2, weight=1)
frame_actions.grid_columnconfigure(3, weight=1)

ttk.Button(frame_actions, text="Launch", command=launch_selected_machine, bootstyle="success").grid(row=0, column=0, sticky="ew", padx=2)
ttk.Button(frame_actions, text=" Add  ", command=add_machine, bootstyle="primary").grid(row=0, column=1, sticky="ew", padx=2)
ttk.Button(frame_actions, text=" Edit ", command=edit_machine, bootstyle="warning").grid(row=0, column=2, sticky="ew", padx=2)
ttk.Button(frame_actions, text="Remove", command=remove_machine, bootstyle="danger").grid(row=0, column=3, sticky="ew", padx=2)

# === Import/Export Actions ===
frame_import_export = ttk.Frame(root)
frame_import_export.pack(pady=5, fill="x", padx=10)

# === Configure columns to expand equally ===
frame_import_export.grid_columnconfigure(0, weight=1)
frame_import_export.grid_columnconfigure(1, weight=1)
frame_import_export.grid_columnconfigure(2, weight=1)

ttk.Button(frame_import_export, text="Import Config", command=import_config, bootstyle="info").grid(row=0, column=0, sticky="ew", padx=2)
ttk.Button(frame_import_export, text="Export Config", command=export_config, bootstyle="info").grid(row=0, column=1, sticky="ew", padx=2)
ttk.Button(frame_import_export, text="Backup", command=lambda: backup_current_config() and status_var.set("Backup created"), bootstyle="secondary").grid(row=0, column=2, sticky="ew", padx=2)

# === Status Bar ===
status_var = ttk.StringVar()
ttk.Label(root, textvariable=status_var, anchor="w", relief="sunken", bootstyle="secondary").pack(fill="x", side="bottom")
status_var.set("Ready")

refresh_machine_list()
root.mainloop()