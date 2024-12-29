import tkinter as tk
from tkinter import messagebox, ttk
import requests
from io import BytesIO
import os

# Download function with progress bar
def download_file(url, dest_path, progress_var):
    try:
        response = requests.get(url, stream=True)
        total_size = int(response.headers.get('content-length', 0))
        downloaded_size = 0
        
        with open(dest_path, 'wb') as f:
            for data in response.iter_content(chunk_size=1024):
                downloaded_size += len(data)
                f.write(data)
                progress_var.set((downloaded_size / total_size) * 100)
                root.update_idletasks()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to download {url}: {str(e)}")

def start_installation():
    selected_packages = []
    if lmephisto_var.get():
        selected_packages.append(("lMephisto", "https://github.com/Fhchcjcjcjcjvkkvk/secret/raw/refs/heads/main/lmephisto.exe"))
    if theripper_var.get():
        selected_packages.append(("theripper", "https://github.com/Fhchcjcjcjcjvkkvk/secret/raw/refs/heads/main/theripper.exe"))
    if hmephisto_var.get():
        selected_packages.append(("hMephisto", "https://github.com/Fhchcjcjcjcjvkkvk/secret/raw/refs/heads/main/hmephisto.exe"))
    if hashing_var.get():
        selected_packages.append(("hashing", "https://github.com/Fhchcjcjcjcjvkkvk/secret/raw/refs/heads/main/hashing.exe"))
    if pdfmephisto_var.get():
        selected_packages.append(("pdfMephisto", "https://github.com/Fhchcjcjcjcjvkkvk/secret/raw/refs/heads/main/pdfmephisto.exe"))
    if test_server_var.get():
        selected_packages.append(("test server", "https://github.com/Fhchcjcjcjcjvkkvk/secret/raw/refs/heads/main/server.exe"))
    
    if not selected_packages:
        messagebox.showwarning("No Selection", "Please select at least one package to install.")
        return

    progress_var.set(0)
    for package_name, url in selected_packages:
        download_file(url, f"{package_name}.exe", progress_var)
    
    messagebox.showinfo("Success", "Installation completed successfully!")

# GUI setup
root = tk.Tk()
root.title("Installer")
root.geometry("400x300")

lmephisto_var = tk.BooleanVar()
theripper_var = tk.BooleanVar()
hmephisto_var = tk.BooleanVar()
hashing_var = tk.BooleanVar()
pdfmephisto_var = tk.BooleanVar()
test_server_var = tk.BooleanVar()

# Checkboxes for selecting packages
tk.Checkbutton(root, text="lMephisto", variable=lmephisto_var).pack()
tk.Checkbutton(root, text="theripper", variable=theripper_var).pack()
tk.Checkbutton(root, text="hMephisto", variable=hmephisto_var).pack()
tk.Checkbutton(root, text="hashing", variable=hashing_var).pack()
tk.Checkbutton(root, text="pdfMephisto", variable=pdfmephisto_var).pack()
tk.Checkbutton(root, text="test server (for lMephisto)", variable=test_server_var).pack()

# Progress bar
progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100, length=300)
progress_bar.pack(pady=20)

# Install button
install_button = tk.Button(root, text="Start Installation", command=start_installation)
install_button.pack()

root.mainloop()
