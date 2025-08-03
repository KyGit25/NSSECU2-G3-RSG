"""
Test Setup Script for Ransomware Simulator Generator

This script creates a safe test environment with sample files
for testing the ransomware simulator generator.
"""

import os
import sys
from pathlib import Path

def create_test_environment():
    """
    Create a test directory with sample files.

    """

    # Create test directory
    test_dir = Path("ransomware_test")
    test_dir.mkdir(exist_ok=True)
    
    # Create subdirectories
    (test_dir / "documents").mkdir(exist_ok=True)
    (test_dir / "images").mkdir(exist_ok=True)
    (test_dir / "data").mkdir(exist_ok=True)
    (test_dir / "protected").mkdir(exist_ok=True)
    
    # Sample file contents
    sample_files = {
        "documents/readme.txt": "sample lockable file",
        "documents/important.doc": "sample lockable file",
        "documents/notes.txt": "sample lockable file",
        "images/photo1.txt": "sample lockable file",
        "images/photo2.txt": "sample lockable file",
        "data/database.txt": "sample lockable file",
        "data/backup.txt": "sample lockable file",
        "config.txt": "sample lockable file",
        "log.txt": "sample lockable file",
        "presentation.txt": "sample lockable file",
    }
    
    # Create sample files
    created_files = []
    for file_path, content in sample_files.items():
        full_path = test_dir / file_path
        try:
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
            created_files.append(str(full_path))
            print(f"\nCreated: {full_path}")
        except Exception as e:
            print(f"Error creating {full_path}: {e}")
    
    # Create protected files to test error handling
    protected_files = []
    try:
        protected_file = test_dir / "protected" / "system_driver.sys"
        with open(protected_file, 'w', encoding='utf-8') as f:
            f.write("This simulates a system file that should be skipped during encryption due to its .sys extension.")
        
        protected_files.append(str(protected_file))
        print(f"\nCreated protected system file: {protected_file}")

        log_file = test_dir / "protected" / "system.log"
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write("This is a log file that should be skipped during encryption.\nLog entry 1\nLog entry 2")
        
        protected_files.append(str(log_file))
        print(f"\nCreated protected log file: {log_file}")
        
    except Exception as e:
        print(f"Error creating protected files: {e}")
    
    print(f"\nTest environment created successfully!")
    print(f"Directory: {test_dir.absolute()}")
    print(f"\nRegular files created: {len(created_files)}")
    print(f"Protected files created: {len(protected_files)}")
    print(f"\nYou can now test the ransomware simulator with this directory: {test_dir.absolute()}")

    return str(test_dir.absolute())

def cleanup_test_environment():
    """
    This function deletes the test directory and all its contents.

    """
    test_dir = Path("ransomware_test")
    
    if test_dir.exists():
        import shutil
        try:
            shutil.rmtree(test_dir)
            print(f"Test environment cleaned up: {test_dir.absolute()}")
        except Exception as e:
            print(f"Error cleaning up test environment: {e}")
    else:
        print("Test environment not found.")

def main():
    print("\nRansomware Simulation Test Setup\n")
    print("1. Create test environment")
    print("2. Cleanup test environment")
    print("3. Exit")
    
    while True:
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == "1":
            create_test_environment()
            break
        elif choice == "2":
            cleanup_test_environment()
            break
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
