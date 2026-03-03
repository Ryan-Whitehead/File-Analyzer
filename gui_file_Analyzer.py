#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog, scrolledtext
import magic
import pathlib
import os

class Analyzer:
    def __init__(self, filename=None):
        self.filename = filename
        self.extension = None
        self.file_signature = None
        self.file_description = None
        self.extension_match = None
        self.suspicious = False
    
    def getFileExtension(self):
        if self.filename:
            abs_path = os.path.abspath(self.filename)
            path_obj = pathlib.Path(abs_path)
            self.extension = path_obj.suffix.lower()
    
    def get_file_signature(self):
        if self.filename:
            abs_path = os.path.abspath(self.filename)
            mime = magic.Magic(mime=True)
            self.file_signature = mime.from_file(abs_path)
            desc = magic.Magic()
            self.file_description = desc.from_file(abs_path)
    
    def check_extension_match(self):
        if not self.extension or not self.file_signature:
            return
        
        extension_to_mime = {
            '.txt': 'text/plain',
            '.pdf': 'application/pdf',
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.zip': 'application/zip',
            '.py': 'text/x-python',
            '.html': 'text/html',
            '.js': 'text/javascript',
            '.css': 'text/css',
            '.json': 'application/json',
            '.xml': 'application/xml',
        }
        
        expected_mime = extension_to_mime.get(self.extension, None)
        if expected_mime:
            self.extension_match = (expected_mime == self.file_signature)
            self.suspicious = not self.extension_match

# Global variable for selected file
selected_file = None

# Function to handle file selection
def select_file():
    global selected_file
    file_path = filedialog.askopenfilename(
        title="Select a file",
        filetypes=[("All files", "*.*")]
    )
    
    if file_path:
        selected_file = file_path
        file_name = os.path.basename(file_path)
        
        # UPDATE THE GUI LABEL
        file_label.config(text=f"📄 Selected: {file_name}", fg="black")
        
        # Optional: print to terminal for debugging
        print(f"Selected file: {file_path}")

# Function to analyze the file
def analyze_file():
    if not selected_file:
        results_text.delete(1.0, tk.END)
        results_text.insert(1.0, "❌ Please select a file first!")
        return
    
    results_text.delete(1.0, tk.END)
    results_text.insert(1.0, "⏳ Analyzing...")
    window.update()  # Update GUI to show the message
    
    try:
        analyzer = Analyzer(selected_file)
        analyzer.getFileExtension()
        analyzer.get_file_signature()
        analyzer.check_extension_match()
        
        results = f"""
{'='*50}
FILE ANALYSIS RESULTS
{'='*50}

📁 File: {os.path.basename(selected_file)}
🔤 Extension: {analyzer.extension}
📄 MIME Type: {analyzer.file_signature}
📝 Description: {analyzer.file_description}

{'='*50}
🔒 SECURITY CHECK
{'='*50}
"""
        
        if analyzer.suspicious:
            results += """
⚠️  WARNING: FILE EXTENSION MISMATCH!

The file extension suggests one type of file,
but the actual content is different.

This could indicate:
• A mislabeled file
• Malware disguised as a safe file
• A file saved with wrong extension
"""
        else:
            if analyzer.extension_match:
                results += "✅ Extension matches file content - File appears safe"
            else:
                results += "ℹ️  Extension not in verification list (check manually)"
        
        results_text.delete(1.0, tk.END)
        results_text.insert(1.0, results)
        
    except Exception as e:
        results_text.delete(1.0, tk.END)
        results_text.insert(1.0, f"❌ Error analyzing file:\n\n{str(e)}")

# Create the main window
window = tk.Tk()
window.title("Magic File Analyzer")
window.geometry("700x500")

# Title
title_label = tk.Label(window, text="🔍 Magic File Analyzer", 
                      font=("Arial", 18, "bold"))
title_label.pack(pady=20)

# File selection area
select_button = tk.Button(window,
                         text="📁 Select File",
                         command=select_file,
                         font=("Arial", 12),
                         bg="#4a6fa5",
                         fg="white",
                         padx=20,
                         pady=10)
select_button.pack(pady=10)

# THIS LABEL NEEDS TO BE UPDATED WHEN FILE IS SELECTED
file_label = tk.Label(window, text="No file selected", 
                     font=("Arial", 10), fg="gray")
file_label.pack()

# Analyze button
analyze_button = tk.Button(window,
                          text="🔍 Analyze File",
                          command=analyze_file,
                          font=("Arial", 12),
                          bg="#51a351",
                          fg="white",
                          padx=20,
                          pady=10)
analyze_button.pack(pady=10)

# Results area
results_label = tk.Label(window, text="Analysis Results:", 
                        font=("Arial", 12, "bold"))
results_label.pack(pady=10)

results_text = scrolledtext.ScrolledText(window,
                                        height=15,
                                        font=("Consolas", 10))
results_text.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

# Start the GUI
window.mainloop()