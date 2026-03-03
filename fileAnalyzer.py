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
        self.filename = input("Enter file path to analyze: ")

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
        Uses pytgon-magic library to dtermine the actual file type by examining
        file headers/magic numbers, not just the extension
        """
        if self.filename:
                abs_path = os.path.abspath(self.filename)

                mime = magic.Magic(mime=True)
                self.file_signature = mime.from_file(abs_path)

                desc = magic.Magic()
                self.file_description = desc.from_file(abs_path)
      
      def check_extension_match(self):
          """
          Compares the file extension with the actual file content type to detect
          mismtaches that could indicate malware or mislabeled files

          Logic:
            1. Maps known extensions top expected MIME types
            2. Compares expected vs actual MIME type
            3. Flags as suspicious if mismatch detcted 
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

      def output(self):
           """
        Displays the analysis results in a formatted report including
        file metadata and security verification results.
        
        Output Format:
        --------------
        1. Header with separators
        2. Basic file information (extension, description, MIME)
        3. Verification section with safety assessment
        4. Warning messages if file appears suspicious
        """
           print("\n" + "="*50)
           print("Magic Number Analysis:")
           print("="*50)
           print(f"file extension: {self.extension}")
           print(f"file command output: {self.file_description}")
           print(f"MIME type: {self.file_signature}")
           #show match result
           print("\n" + "-"*50)
           print("EXTENSION VERIFICATION:")
        
           if self.suspicious:
                print("⚠️  WARNING: File extension does NOT match actual content!")
                print(f"   Extension '{self.extension}' suggests one type,")
                print(f"   but file actually contains: {self.file_description}")
           else:
                if self.extension_match:
                    print("✅ Extension matches file content")
                else:
                    print("ℹ️  Extension not in common list (check manually)")
           print("="*50)

def main():
    """
    Main execution function demonstrating the analyzer workflow.
    
    Steps:
    ------
    1. Create Analyzer instance
    2. Get file path from user
    3. Extract file extension
    4. Analyze file signature/magic numbers
    5. Verify extension matches content
    6. Display results
    """
    # Create analyzer object
    analyzer = Analyzer()

    # Get user input 
    analyzer.userFile()

    # Process the file
    analyzer.getFileExtension()
    analyzer.get_file_signature()
    
    # Check if extension matches content
    analyzer.check_extension_match()

    # Display results
    analyzer.output()


if __name__ == "__main__":
    main()
