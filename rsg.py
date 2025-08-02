#!/usr/bin/env python3
"""
Ransomware Simulation Tool
==========================

An educational tool designed to simulate ransomware behavior in a controlled environment.
This tool demonstrates how ransomware operates by encrypting files and creating ransom notes,
while providing safe decryption capabilities for learning purposes.

Author: Network Security Course Project
Date: August 2025
Version: 1.0

WARNING: This tool is for educational use only in lab environments.
DO NOT use on production systems or personal files.
"""

import os
import sys
from cryptography.fernet import Fernet  # For AES encryption
import logging
from datetime import datetime
import argparse
from pathlib import Path

# Constants
RANSOM_EXTENSION = ".locked"
RANSOM_NOTE_FILENAME = "README_RANSOM.txt"
LOG_FILE = "ransom_simulator.log"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit for safety
SUPPORTED_EXTENSIONS = {'.txt', '.doc', '.docx', '.pdf', '.jpg', '.png', '.mp3', '.mp4'}
EXCLUDED_EXTENSIONS = {'.exe', '.dll', '.sys', '.log', '.tmp'}
XOR_KEY = b"education2025"  # Fixed XOR key for educational purposes

def display_warning():
    """
    Display a comprehensive warning message about the tool's educational purpose.
    
    This function ensures users understand the tool is for educational use only
    and requires explicit acknowledgment before proceeding.
    """
    warning = """
    ╔══════════════════════════════════════════════════════════════╗
    ║             WARNING: RANSOMWARE SIMULATION TOOL              ║
    ╠══════════════════════════════════════════════════════════════╣
    ║                                                              ║
    ║  This is an EDUCATIONAL tool designed to simulate            ║
    ║  ransomware behavior in a CONTROLLED ENVIRONMENT.            ║
    ║                                                              ║
    ║  DO NOT run this tool on:                                    ║
    ║  • Production systems                                        ║
    ║  • Personal files                                            ║
    ║  • Systems containing important data                         ║
    ║                                                              ║
    ║  Use ONLY on dedicated lab machines or virtual environments. ║
    ║                                                              ║
    ║  By continuing, you acknowledge this is for educational      ║
    ║  use only and accept full responsibility for its usage.      ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(warning)
    confirmation = input("Type 'I UNDERSTAND' to continue or Ctrl+C to abort: ").strip()
    if confirmation != "I UNDERSTAND":
        print("Confirmation not received. Exiting for safety.")
        sys.exit(0)
    print("Proceeding with simulation...\n")

def find_encrypted_files(target_dir):
    """
    Find all encrypted (.locked) files in the target directory.
    
    Args:
        target_dir (str): Directory to search for encrypted files
        
    Returns:
        list: List of encrypted file paths
    """
    encrypted_files = []
    
    try:
        for root, _, files in os.walk(target_dir):
            for file in files:
                if file.endswith(RANSOM_EXTENSION):
                    file_path = os.path.join(root, file)
                    encrypted_files.append(file_path)
    except Exception as e:
        logging.error(f"Error finding encrypted files: {e}")
    
    return encrypted_files

def is_safe_file(file_path):
    """
    Determine if a file is safe to process based on size, extension, and location.
    
    Args:
        file_path (str): Path to the file to check
        
    Returns:
        bool: True if file is safe to process, False otherwise
    """
    try:
        # Check file size
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            logging.warning(f"Skipping large file: {file_path}")
            return False
        
        # Check file extension
        file_ext = Path(file_path).suffix.lower()
        if file_ext in EXCLUDED_EXTENSIONS:
            logging.warning(f"Skipping excluded file type: {file_path}")
            return False
        
        # Check if file is in system directories (basic protection)
        system_paths = ['windows', 'system32', 'program files']
        file_path_lower = file_path.lower()
        if any(sys_path in file_path_lower for sys_path in system_paths):
            logging.warning(f"Skipping system file: {file_path}")
            return False
        
        return True
    except (OSError, IOError) as e:
        logging.error(f"Error checking file safety for {file_path}: {e}")
        return False

def scan_directory(target_dir):
    """
    Recursively scan directory and return list of safe files to process.
    
    Args:
        target_dir (str): Target directory to scan
        
    Returns:
        list: List of file paths that are safe to process
        
    Raises:
        ValueError: If target directory doesn't exist or isn't accessible
    """
    if not os.path.isdir(target_dir):
        raise ValueError(f"Invalid directory: {target_dir}")
    
    file_list = []
    skipped_count = 0
    
    print(f"Scanning directory: {target_dir}")
    
    try:
        for root, _, files in os.walk(target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip hidden files, our own files, and already encrypted files
                if (file.startswith('.') or 
                    file == RANSOM_NOTE_FILENAME or 
                    file == LOG_FILE or
                    file.endswith(RANSOM_EXTENSION)):
                    skipped_count += 1
                    continue
                
                # Check if file is safe to process
                if is_safe_file(file_path):
                    file_list.append(file_path)
                else:
                    skipped_count += 1
                    
    except PermissionError as e:
        logging.error(f"Permission denied accessing directory: {e}")
        raise ValueError(f"Cannot access directory: {target_dir}")
    
    print(f"Found {len(file_list)} files to process, skipped {skipped_count} files")
    logging.info(f"Scanned {target_dir}: {len(file_list)} files found, {skipped_count} skipped")
    
    return file_list

def xor_encrypt_decrypt(data, key):
    """
    Encrypt or decrypt data using XOR cipher (symmetric operation).
    
    Args:
        data (bytes): Data to encrypt/decrypt
        key (bytes): XOR key
        
    Returns:
        bytes: Encrypted/decrypted data
    """
    result = bytearray()
    key_len = len(key)
    
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % key_len])
    
    return bytes(result)

def simulate_encryption(file_list, encryption_method="rename", key=None):
    """
    Simulate encryption by renaming files and optionally encrypting contents.
    
    Args:
        file_list (list): List of file paths to encrypt
        encryption_method (str): "rename", "xor", or "aes"
        key (bytes): Encryption key (required for AES and XOR)
        
    Returns:
        list: List of successfully encrypted file paths
    """
    encrypted_files = []
    failed_files = []
    
    print(f"Starting encryption simulation using {encryption_method} method...")
    
    for i, file_path in enumerate(file_list, 1):
        try:
            # Skip already encrypted files
            if file_path.endswith(RANSOM_EXTENSION):
                continue
                
            new_path = file_path + RANSOM_EXTENSION
            print(f"Processing {i}/{len(file_list)}: {os.path.basename(file_path)}")
            
            # Apply encryption based on method
            if encryption_method == "aes" and key:
                encrypt_file_aes(file_path, new_path, key)
            elif encryption_method == "xor" and key:
                encrypt_file_xor(file_path, new_path, key)
            else:
                # Just rename the file to simulate encryption
                os.rename(file_path, new_path)
            
            encrypted_files.append(new_path)
            
        except Exception as e:
            error_msg = f"Error processing {file_path}: {str(e)}"
            logging.error(error_msg)
            print(f"  ERROR: {error_msg}")
            failed_files.append(file_path)
            continue
    
    print(f"\nEncryption complete: {len(encrypted_files)} files encrypted, {len(failed_files)} failed")
    if failed_files:
        logging.warning(f"Failed to encrypt {len(failed_files)} files")
        
    return encrypted_files

def encrypt_file_aes(input_path, output_path, key):
    """
    Encrypt file contents using AES encryption.
    
    Args:
        input_path (str): Path to original file
        output_path (str): Path for encrypted file
        key (bytes): AES encryption key
    """
    fernet = Fernet(key)
    
    with open(input_path, 'rb') as f:
        original = f.read()
    
    encrypted = fernet.encrypt(original)
    
    with open(output_path, 'wb') as f:
        f.write(encrypted)
    
    # Remove original file
    os.remove(input_path)
    logging.info(f"AES encrypted: {input_path} -> {output_path}")

def encrypt_file_xor(input_path, output_path, key):
    """
    Encrypt file contents using XOR cipher.
    
    Args:
        input_path (str): Path to original file
        output_path (str): Path for encrypted file
        key (bytes): XOR encryption key
    """
    with open(input_path, 'rb') as f:
        original = f.read()
    
    encrypted = xor_encrypt_decrypt(original, key)
    
    with open(output_path, 'wb') as f:
        f.write(encrypted)
    
    # Remove original file
    os.remove(input_path)
    logging.info(f"XOR encrypted: {input_path} -> {output_path}")

def encrypt_file(input_path, output_path, key):
    """
    Legacy function - encrypt file using AES (for backward compatibility).
    
    Args:
        input_path (str): Path to original file
        output_path (str): Path for encrypted file
        key (bytes): AES encryption key
    """
    encrypt_file_aes(input_path, output_path, key)

def create_ransom_note(target_dir, encryption_method="rename"):
    """
    Create a ransom note file in the target directory with recovery instructions.
    
    Args:
        target_dir (str): Directory where ransom note will be created
        encryption_method (str): Type of encryption used
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    note_content = f"""
╔══════════════════════════════════════════════════════════════╗
║                YOUR FILES HAVE BEEN ENCRYPTED!               ║
║                      (SIMULATION)                            ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  This is part of an ethical hacking educational exercise.    ║
║                                                              ║
║  Encryption Details:                                         ║
║  • Method: {encryption_method.upper()}                       ║
║  • Timestamp: {timestamp}                                    ║
║  • Extension: {RANSOM_EXTENSION}                             ║
║                                                              ║
║  TO RECOVER YOUR FILES:                                      ║
║  1. Run this tool again with decryption option               ║
║  2. Use the same encryption method that was used             ║
║  3. For real encryption, use the key that was displayed      ║
║                                                              ║
║  Educational Note:                                           ║
║  This demonstrates how ransomware operates. In real          ║
║  attacks, files would be permanently encrypted without       ║
║  the decryption key held by attackers.                       ║
║                                                              ║
║  Remember: This is just a simulation for educational         ║
║  purposes. No actual harm has been done to your files.       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

Technical Information:
- Original tool: Ransomware Simulation Tool v1.0
- Purpose: Educational demonstration
- Safe recovery: Available through the same tool
- Log file: {LOG_FILE}

For questions about this simulation, contact your instructor.
    """
    
    note_path = os.path.join(target_dir, RANSOM_NOTE_FILENAME)
    try:
        with open(note_path, 'w', encoding='utf-8') as f:
            f.write(note_content)
        print(f"Ransom note created: {note_path}")
        logging.info(f"Ransom note created at: {note_path}")
    except Exception as e:
        logging.error(f"Failed to create ransom note: {e}")
        print(f"Warning: Could not create ransom note: {e}")

def decrypt_files(file_list, encryption_method="rename", key=None):
    """
    Restore original filenames and decrypt contents if encrypted.
    
    Args:
        file_list (list): List of encrypted file paths
        encryption_method (str): "rename", "xor", or "aes"
        key (bytes): Decryption key (required for AES and XOR)
        
    Returns:
        list: List of successfully decrypted file paths
    """
    decrypted_files = []
    failed_files = []
    
    print(f"Starting decryption using {encryption_method} method...")
    
    for i, file_path in enumerate(file_list, 1):
        try:
            if not file_path.endswith(RANSOM_EXTENSION):
                continue
                
            original_path = file_path[:-len(RANSOM_EXTENSION)]
            print(f"Decrypting {i}/{len(file_list)}: {os.path.basename(original_path)}")
            
            if encryption_method == "aes" and key:
                decrypt_file_aes(file_path, original_path, key)
            elif encryption_method == "xor" and key:
                decrypt_file_xor(file_path, original_path, key)
            else:
                os.rename(file_path, original_path)
            
            decrypted_files.append(original_path)
            
        except Exception as e:
            error_msg = f"Error decrypting {file_path}: {str(e)}"
            logging.error(error_msg)
            print(f"  ERROR: {error_msg}")
            failed_files.append(file_path)
            continue
    
    print(f"\nDecryption complete: {len(decrypted_files)} files restored, {len(failed_files)} failed")
    if failed_files:
        logging.warning(f"Failed to decrypt {len(failed_files)} files")
        
    return decrypted_files

def decrypt_file_aes(input_path, output_path, key):
    """
    Decrypt file using AES decryption.
    
    Args:
        input_path (str): Path to encrypted file
        output_path (str): Path for decrypted file
        key (bytes): AES decryption key
    """
    fernet = Fernet(key)
    
    with open(input_path, 'rb') as f:
        encrypted = f.read()
    
    try:
        decrypted = fernet.decrypt(encrypted)
    except Exception as e:
        raise ValueError(f"AES decryption failed - wrong key? Error: {e}")
    
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    
    os.remove(input_path)
    logging.info(f"AES decrypted: {input_path} -> {output_path}")

def decrypt_file_xor(input_path, output_path, key):
    """
    Decrypt file using XOR cipher.
    
    Args:
        input_path (str): Path to encrypted file
        output_path (str): Path for decrypted file
        key (bytes): XOR decryption key
    """
    with open(input_path, 'rb') as f:
        encrypted = f.read()
    
    decrypted = xor_encrypt_decrypt(encrypted, key)
    
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    
    os.remove(input_path)
    logging.info(f"XOR decrypted: {input_path} -> {output_path}")

def decrypt_file(input_path, output_path, key):
    """
    Legacy function - decrypt file using AES (for backward compatibility).
    
    Args:
        input_path (str): Path to encrypted file
        output_path (str): Path for decrypted file
        key (bytes): AES decryption key
    """
    decrypt_file_aes(input_path, output_path, key)

def setup_logging():
    """
    Configure comprehensive logging system for tracking all operations.
    
    Sets up both file and console logging with appropriate levels.
    """
    # Clear any existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    
    # File handler
    file_handler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Console handler for errors
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    
    # Configure root logger
    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[file_handler, console_handler]
    )
    
    # Log session start
    logging.info("="*60)
    logging.info("Ransomware Simulator Session Started")
    logging.info(f"Python version: {sys.version}")
    logging.info(f"Working directory: {os.getcwd()}")
    logging.info("="*60)

def log_operation(operation, file_list, additional_info=None):
    """
    Log file operations with detailed information.
    
    Args:
        operation (str): Type of operation performed
        file_list (list): List of files affected
        additional_info (dict): Additional information to log
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Log to main log file
    logging.info(f"Operation: {operation}")
    logging.info(f"Files affected: {len(file_list)}")
    
    if additional_info:
        for key, value in additional_info.items():
            logging.info(f"{key}: {value}")
    
    # Log each file
    for file_path in file_list:
        logging.debug(f"  {operation}: {file_path}")
    
    # Also maintain the simple log format for easy reading
    try:
        with open(LOG_FILE.replace('.log', '_summary.log'), 'a', encoding='utf-8') as log:
            log.write(f"\n{timestamp} - {operation} ({len(file_list)} files):\n")
            if additional_info:
                for key, value in additional_info.items():
                    log.write(f"  {key}: {value}\n")
            for file in file_list[:10]:  # Limit to first 10 files in summary
                log.write(f"  {file}\n")
            if len(file_list) > 10:
                log.write(f"  ... and {len(file_list) - 10} more files\n")
    except Exception as e:
        logging.error(f"Failed to write summary log: {e}")

def get_operation_mode():
    """
    Get operation mode choice from user.
    
    Returns:
        str: "encrypt" or "decrypt"
    """
    print("\nSelect operation mode:")
    print("1. Encrypt files (simulate ransomware attack)")
    print("2. Decrypt files (recover encrypted files)")
    
    while True:
        choice = input("Enter choice (1-2): ").strip()
        if choice == "1":
            return "encrypt"
        elif choice == "2":
            return "decrypt"
        else:
            print("Invalid choice. Please enter 1 or 2.")

def get_encryption_method():
    """
    Get encryption method choice from user with validation.
    
    Returns:
        tuple: (method_name, requires_key)
    """
    print("\nSelect encryption method:")
    print("1. Rename only (safest - just changes file extensions)")
    print("2. XOR cipher (reversible encryption)")
    print("3. AES encryption (strong encryption)")
    
    while True:
        choice = input("Enter choice (1-3): ").strip()
        if choice == "1":
            return "rename", False
        elif choice == "2":
            return "xor", True
        elif choice == "3":
            return "aes", True
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

def get_decryption_key(encryption_method):
    """
    Get decryption key from user input.
    
    Args:
        encryption_method (str): The encryption method used
        
    Returns:
        bytes: The decryption key
    """
    if encryption_method == "xor":
        print(f"XOR encryption uses a fixed key: {XOR_KEY.decode()}")
        return XOR_KEY
    elif encryption_method == "aes":
        while True:
            key_input = input("Enter the AES decryption key: ").strip()
            if not key_input:
                print("Key cannot be empty. Please enter the key.")
                continue
            try:
                key = key_input.encode()
                # Test if it's a valid Fernet key
                Fernet(key)
                return key
            except Exception:
                print("Invalid AES key format. Please enter a valid Fernet key.")
                continue
    else:
        return None

def validate_directory(target_dir):
    """
    Validate that the target directory is safe for simulation.
    
    Args:
        target_dir (str): Directory path to validate
        
    Returns:
        bool: True if directory is safe to use
    """
    # Convert to absolute path
    target_dir = os.path.abspath(target_dir)
    
    # Check if it's a system directory
    dangerous_paths = [
        'c:\\windows',
        'c:\\program files',
        'c:\\program files (x86)',
        'c:\\users\\' + os.environ.get('USERNAME', '') + '\\documents',
        'c:\\users\\' + os.environ.get('USERNAME', '') + '\\desktop'
    ]
    
    target_lower = target_dir.lower()
    for dangerous in dangerous_paths:
        if target_lower.startswith(dangerous.lower()):
            print(f"ERROR: Cannot target system directory: {target_dir}")
            return False
    
    # Recommend creating a test directory
    if not target_dir.lower().endswith(('test', 'lab', 'sandbox', 'demo')):
        print(f"WARNING: Directory name doesn't suggest a test environment.")
        print(f"Recommended: Create a test directory like 'ransomware_test'")
        confirm = input("Continue anyway? (y/n): ").lower()
        if confirm != 'y':
            return False
    
    return True

def main():
    """
    Main function that orchestrates the ransomware simulation.
    
    Handles user interaction, validation, encryption/decryption operations,
    and comprehensive logging of all activities.
    """
    print("Ransomware Simulation Tool v1.0")
    print("Educational Network Security Project")
    print("-" * 50)
    
    # Display warning and get confirmation
    display_warning()
    
    # Setup logging
    setup_logging()
    
    try:
        # Get operation mode
        operation_mode = get_operation_mode()
        
        # Get and validate target directory
        while True:
            target_dir = input("Enter target directory path: ").strip()
            if not target_dir:
                print("Please enter a directory path.")
                continue
                
            if not os.path.isdir(target_dir):
                print("Error: Directory does not exist.")
                continue
                
            if validate_directory(target_dir):
                break
        
        target_dir = os.path.abspath(target_dir)
        print(f"Target directory: {target_dir}")
        
        if operation_mode == "encrypt":
            # ENCRYPTION MODE
            print("\n" + "="*50)
            print("ENCRYPTION MODE")
            print("="*50)
            
            # Get encryption method
            encryption_method, requires_key = get_encryption_method()
            
            # Generate or get key if needed
            key = None
            if requires_key:
                if encryption_method == "aes":
                    key = Fernet.generate_key()
                    print(f"\nIMPORTANT: Save this AES key for decryption!")
                    print(f"Key: {key.decode()}")
                    print("WARNING: Without this key, files cannot be decrypted!")
                    input("\nPress Enter after you have saved the key...")
                elif encryption_method == "xor":
                    key = XOR_KEY
                    print(f"\nUsing XOR key: {key.decode()}")
            
            # Scan directory for files
            try:
                files = scan_directory(target_dir)
                if len(files) == 0:
                    print("No files found to encrypt. Exiting.")
                    return
            except ValueError as e:
                print(f"Error: {e}")
                return
            
            # Confirm operation
            print(f"\nReady to simulate encryption on {len(files)} files using {encryption_method} method.")
            if input("Proceed with encryption simulation? (y/n): ").lower() != 'y':
                print("Encryption cancelled.")
                return
            
            # Perform encryption
            print("\n" + "="*50)
            print("STARTING ENCRYPTION SIMULATION")
            print("="*50)
            
            encrypted_files = simulate_encryption(files, encryption_method, key)
            
            if encrypted_files:
                create_ransom_note(target_dir, encryption_method)
                
                # Log the operation
                log_info = {
                    "method": encryption_method,
                    "target_directory": target_dir,
                    "files_encrypted": len(encrypted_files),
                    "key_used": "Yes" if requires_key else "No"
                }
                log_operation("ENCRYPTION_SIMULATION", encrypted_files, log_info)
                
                print(f"\nEncryption simulation complete!")
                print(f"Files encrypted: {len(encrypted_files)}")
                print(f"Ransom note created: {os.path.join(target_dir, RANSOM_NOTE_FILENAME)}")
                print(f"Log file: {LOG_FILE}")
                
                if requires_key:
                    print(f"\nRemember your decryption key: {key.decode()}")
                    print("Run this tool again in 'decrypt' mode to restore files.")
            else:
                print("No files were encrypted. Check the log for details.")
        
        else:
            # DECRYPTION MODE
            print("\n" + "="*50)
            print("DECRYPTION MODE")
            print("="*50)
            
            # Find encrypted files
            encrypted_files = find_encrypted_files(target_dir)
            
            if not encrypted_files:
                print("No encrypted files found in the specified directory.")
                return
            
            print(f"Found {len(encrypted_files)} encrypted files")
            
            # Get encryption method used
            encryption_method, requires_key = get_encryption_method()
            
            # Get decryption key if needed
            key = None
            if requires_key:
                key = get_decryption_key(encryption_method)
            
            # Confirm decryption
            if input(f"\nProceed with decryption of {len(encrypted_files)} files? (y/n): ").lower() != 'y':
                print("Decryption cancelled.")
                return
            
            print("\n" + "="*50)
            print("STARTING DECRYPTION")
            print("="*50)
            
            decrypted_files = decrypt_files(encrypted_files, encryption_method, key)
            
            if decrypted_files:
                # Log decryption
                log_info = {
                    "method": encryption_method,
                    "target_directory": target_dir,
                    "files_decrypted": len(decrypted_files)
                }
                log_operation("DECRYPTION", decrypted_files, log_info)
                
                print(f"\nDecryption complete!")
                print(f"Files restored: {len(decrypted_files)}")
                
                # Clean up ransom note
                note_path = os.path.join(target_dir, RANSOM_NOTE_FILENAME)
                try:
                    os.remove(note_path)
                    print("Ransom note removed.")
                except:
                    pass
            else:
                print("No files were decrypted. Check the log for details.")
        
        print(f"\nSession complete. Check {LOG_FILE} for detailed logs.")
        
    except KeyboardInterrupt:
        print("\n\nOperation interrupted by user.")
        logging.info("Operation interrupted by user (Ctrl+C)")
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        print(f"\nERROR: {error_msg}")
        logging.error(error_msg, exc_info=True)
    finally:
        logging.info("Ransomware simulation session ended")
        logging.info("="*60)

if __name__ == "__main__":
    main()