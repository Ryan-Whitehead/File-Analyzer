import tkinter as tk
from tkinter import filedialog 
from tkinter import scrolledtext
import magic
import pathlib
import os

class Analyzer:
      """
      A file analyzer that examines file signatures, extensions, and MIME types
      to verify file integrity and detect mismatches 
      """
      def __init__(self, filename=None):
        """
        Initializes the Analyzer object with file metadata attributes.
        
        Parameters:
        -----------
        filename : str, optional
            Path to the file to be analyzed. Can be None if set later via userFile().
        """
        self.filename = filename
        self.extension = None
        self.file_signature = None
        self.file_description = None
        self.extension_match = None
        self.suspicious = False

      def userFile(self):
        """
        Prompts the user to input a file path and stores it in the analyzer.
        """
        while True:
            self.filename = input("Enter file path to analyze: ")
            if os.path.exists(self.filename):
                break
            print(f"❌ File not found: {self.filename}")
            print("Please enter a valid file path.")

      def getFileExtension(self):
           """
           Extracts and stores the file extension from the current filename.
           """
           if self.filename:
               abs_path = os.path.abspath(self.filename)
               path_obj = pathlib.Path(abs_path)
               self.extension = path_obj.suffix.lower()

      def get_file_signature(self):
        """
        Uses python-magic library to determine the actual file type by examining
        file headers/magic numbers, not just the extension
        """
        if self.filename:
            abs_path = os.path.abspath(self.filename)  # Convert to absolute path
            mime = magic.Magic(mime=True)
            self.file_signature = mime.from_file(abs_path)  # Use abs_path

            desc = magic.Magic()
            self.file_description = desc.from_file(abs_path)

      def check_extension_match(self):
          """
          Compares the file extension with the actual file content type to detect
          mismatches that could indicate malware or mislabeled files

          Logic:
            1. Maps known extensions to expected MIME types
            2. Compares expected vs actual MIME type
            3. Flags as suspicious if mismatch detected 
          """
          if not self.extension or not self.file_signature:
              return
          # Map extensions to expected MIME types
          extension_to_mime = {
            '.txt': 'text/plain',
            '.pdf': 'application/pdf',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
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

#Window
window = tk.Tk()
window.title("File Analyzer")
window.geometry("600x400") #Width x Height
selected_file = None

#Label 
label = tk.Label(window, text="File Analyzer GUI", font=("Arial", 16))
label.pack(pady=20)

def select_file():
    file_path = filedialog.askopenfilename(
        title="Select a file",
        filetypes=[("All files", "*.*")]
        )
    if file_path:
            print(f"Selected file: {file_path}")

select_button = tk.Button(window,
                          text="📁 Select File", 
                         command=select_file,
                         font=("Arial", 12),
                         bg="lightblue",
                         padx=20,
                         pady=10)
select_button.pack(pady=20)

file_label =tk.Label(window, text="No file selected", fg="gray")
file_label.pack(pady=10)

# Update the select_file function:
def select_file():
    # Open a file dialog
    file_path = filedialog.askopenfilename(
        title="Select a file",
        filetypes=[("All files", "*.*")]
    )
    
    if file_path:
        # Update the label with file name
        file_name = os.path.basename(file_path)
        file_label.config(text=f"Selected: {file_name}", fg="black")
        
        # Store the file path for later use
        global selected_file  # We'll improve this later
        selected_file = file_path
#Function to analyze the file
def analyze_file():
    if not selected_file:
        print("Please select a file first!")
        return
    
    # Use your Analyzer class
    analyzer = Analyzer(selected_file)
    analyzer.getFileExtension()
    analyzer.get_file_signature()
    analyzer.check_extension_match()
    
    # Display results (for now, just print)
    print(f"Extension: {analyzer.extension}")
    print(f"MIME Type: {analyzer.file_signature}")
    print(f"Description: {analyzer.file_description}")
    print(f"Suspicious: {analyzer.suspicious}")

# Add analyze button (after the select button)
analyze_button = tk.Button(window,
                          text="🔍 Analyze File",
                          command=analyze_file,
                          font=("Arial", 12),
                          bg="lightgreen",
                          padx=20,
                          pady=10)
analyze_button.pack(pady=10)

results_text = scrolledtext.ScrolledText(window,
                                        height=10,
                                        width=50,
                                        font=("Consolas", 10))
results_text.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

def analyze_file():
    if not selected_file:
        #display error in GUI
        results_text.delete(1.0, tk.END)
        results_text.insert(1.0, "Please select a file first")
        return
    
    results_text.delete(1.0, tk.END)

    try:
        analyzer = Analyzer(selected_file)
        analyzer.getFileExtension()
        analyzer.get_file_signature()
        analyzer.check_extension_match()
        
        # Create results string
        results = f"""
{'='*40}
FILE ANALYSIS RESULTS
{'='*40}

File: {os.path.basename(selected_file)}
Extension: {analyzer.extension}
MIME Type: {analyzer.file_signature}
Description: {analyzer.file_description}

{'='*40}
SECURITY CHECK
{'='*40}
"""
        
        if analyzer.suspicious:
            results += "⚠️ WARNING: Extension mismatch!\nFile may be suspicious."
        else:
            if analyzer.extension_match:
                results += "✅ Extension matches content"
            else:
                results += "ℹ️ Extension not in verification list"
        
        # Display in text area
        results_text.insert(1.0, results)
        
    except Exception as e:
        results_text.insert(1.0, f"❌ Error analyzing file:\n{str(e)}")


window.mainloop()

