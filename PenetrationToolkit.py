import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import socket
import os
import requests
import hashlib
import subprocess

# Port Scanner
def port_scanner():
    target = target_entry.get()
    ports = port_entry.get()
    if not target or not ports:
        messagebox.showerror("Error", "Please enter a target and ports.")
        return

    try:
        ports = [int(port.strip()) for port in ports.split(",")]
        open_ports = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
        result_text.insert(tk.END, f"Open ports on {target}: {open_ports}\n")
    except Exception as e:
        result_text.insert(tk.END, f"Error in port scanning: {e}\n")

# Ping Test
def ping_test():
    target = target_entry.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target.")
        return

    try:
        response = os.system(f"ping -c 1 {target}" if os.name != 'nt' else f"ping -n 1 {target}")
        if response == 0:
            result_text.insert(tk.END, f"Ping to {target}: SUCCESS\n")
        else:
            result_text.insert(tk.END, f"Ping to {target}: FAILED\n")
    except Exception as e:
        result_text.insert(tk.END, f"Error in pinging: {e}\n")

# HTTP Header Fetcher
def fetch_headers():
    target = target_entry.get()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = f"http://{target}"

    try:
        response = requests.get(target, timeout=5)
        headers = response.headers
        result_text.insert(tk.END, f"HTTP Headers for {target}:\n")
        for key, value in headers.items():
            result_text.insert(tk.END, f"{key}: {value}\n")
        result_text.insert(tk.END, "\n")
    except Exception as e:
        result_text.insert(tk.END, f"Error fetching headers: {e}\n")

# Hash Generator
def generate_hash():
    input_text = hash_entry.get()
    algorithm = algo_var.get()

    if not input_text:
        messagebox.showerror("Error", "Please enter text or select a file.")
        return

    try:
        if os.path.isfile(input_text):
            with open(input_text, "rb") as f:
                data = f.read()
        else:
            data = input_text.encode()

        hash_func = hashlib.new(algorithm)
        hash_func.update(data)
        result_text.insert(tk.END, f"{algorithm.upper()} hash: {hash_func.hexdigest()}\n")
    except Exception as e:
        result_text.insert(tk.END, f"Error generating hash: {e}\n")

# Execute Custom Command
def execute_command():
    command = command_entry.get()
    if not command:
        messagebox.showerror("Error", "Please enter a command.")
        return

    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        result_text.insert(tk.END, f"Command output:\n{result}\n")
    except Exception as e:
        result_text.insert(tk.END, f"Error executing command: {e}\n")

# GUI Setup
root = tk.Tk()
root.title("Penetration Testing Toolkit")

# Target Entry
tk.Label(root, text="Target:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
target_entry = tk.Entry(root, width=50)
target_entry.grid(row=0, column=1, padx=5, pady=5)

# Port Scanner
tk.Label(root, text="Ports (comma-separated):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
port_entry = tk.Entry(root, width=50)
port_entry.grid(row=1, column=1, padx=5, pady=5)
tk.Button(root, text="Scan Ports", command=port_scanner).grid(row=1, column=2, padx=5, pady=5)

# Ping Test
tk.Button(root, text="Ping Test", command=ping_test).grid(row=2, column=1, padx=5, pady=5)

# HTTP Header Fetcher
tk.Button(root, text="Fetch HTTP Headers", command=fetch_headers).grid(row=3, column=1, padx=5, pady=5)

# Hash Generator
tk.Label(root, text="Text/File for Hash:").grid(row=4, column=0, padx=5, pady=5, sticky="e")
hash_entry = tk.Entry(root, width=50)
hash_entry.grid(row=4, column=1, padx=5, pady=5)
algo_var = tk.StringVar(value="md5")
tk.OptionMenu(root, algo_var, "md5", "sha1", "sha256", "sha512").grid(row=4, column=2, padx=5, pady=5)
tk.Button(root, text="Generate Hash", command=generate_hash).grid(row=4, column=3, padx=5, pady=5)

# Custom Command Execution
tk.Label(root, text="Custom Command:").grid(row=5, column=0, padx=5, pady=5, sticky="e")
command_entry = tk.Entry(root, width=50)
command_entry.grid(row=5, column=1, padx=5, pady=5)
tk.Button(root, text="Execute", command=execute_command).grid(row=5, column=2, padx=5, pady=5)

# Result Display
result_text = scrolledtext.ScrolledText(root, width=80, height=20)
result_text.grid(row=6, column=0, columnspan=4, padx=5, pady=5)

root.mainloop()
