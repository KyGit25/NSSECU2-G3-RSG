#!/usr/bin/env python3
"""
================================================
Test Setup Script for Ransomware Simulation Tool
================================================

This script creates a safe test environment with sample files
for testing the ransomware simulation tool.
"""

import os
import sys
from pathlib import Path

def create_test_environment():
    """Create a test directory with sample files."""
    
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
        "documents/readme.txt": "This is a sample text file for testing the ransomware simulator.",
        "documents/important.doc": "This simulates an important document that would be targeted by ransomware.",
        "documents/notes.txt": "Sample notes file\nLine 2\nLine 3\nEnd of file",
        "images/photo1.txt": "This simulates an image file (using .txt for safety)",
        "images/photo2.txt": "Another simulated image file for testing",
        "data/database.txt": "This simulates a database file that ransomware would target",
        "data/backup.txt": "Simulated backup file",
        "config.txt": "Sample configuration file in root directory",
        "log.txt": "Sample log file with multiple lines\nEntry 1\nEntry 2\nEntry 3",
        "presentation.txt": "This simulates a presentation file",
        "protected/system_file.txt": "This simulates a protected system file that should cause access errors"
    }
    
    # Create sample files
    created_files = []
    for file_path, content in sample_files.items():
        full_path = test_dir / file_path
        try:
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
            created_files.append(str(full_path))
            print(f"Created: {full_path}")
        except Exception as e:
            print(f"Error creating {full_path}: {e}")
    
    # Create protected/read-only files to test error handling
    protected_files = []
    try:
        # Create a read-only file
        readonly_file = test_dir / "protected" / "readonly_file.txt"
        with open(readonly_file, 'w', encoding='utf-8') as f:
            f.write("This is a read-only file that should cause permission errors when trying to encrypt.")
        
        # Make the file read-only on Windows
        if os.name == 'nt':  # Windows
            os.system(f'attrib +R "{readonly_file}"')
        else:  # Unix-like systems
            os.chmod(readonly_file, 0o444)
        
        protected_files.append(str(readonly_file))
        print(f"Created read-only file: {readonly_file}")
        
        # Create a file in a read-only directory
        readonly_dir = test_dir / "readonly_dir"
        readonly_dir.mkdir(exist_ok=True)
        
        readonly_dir_file = readonly_dir / "file_in_readonly_dir.txt"
        with open(readonly_dir_file, 'w', encoding='utf-8') as f:
            f.write("This file is in a read-only directory.")
        
        # Make the directory read-only
        if os.name == 'nt':  # Windows
            os.system(f'attrib +R "{readonly_dir}"')
        else:  # Unix-like systems
            os.chmod(readonly_dir, 0o555)
        
        protected_files.append(str(readonly_dir_file))
        print(f"Created file in read-only directory: {readonly_dir_file}")
        
    except Exception as e:
        print(f"Error creating protected files: {e}")
    
    print(f"\nTest environment created successfully!")
    print(f"Directory: {test_dir.absolute()}")
    print(f"Regular files created: {len(created_files)}")
    print(f"Protected files created: {len(protected_files)}")
    print(f"\nFiles for error handling testing:")
    for pf in protected_files:
        print(f"  - {pf}")
    print(f"\nYou can now test the ransomware simulator with this directory:")
    print(f"Target directory: {test_dir.absolute()}")
    print(f"\nNote: The ransomware simulator should handle protected files gracefully,")
    print(f"skip them, and inform the user about files that cannot be processed.")
    
    return str(test_dir.absolute())

def cleanup_test_environment():
    """Remove the test environment."""
    test_dir = Path("ransomware_test")
    
    if test_dir.exists():
        import shutil
        try:
            # Remove read-only attributes before deletion on Windows
            if os.name == 'nt':
                # Remove read-only attribute from files and directories
                for root, dirs, files in os.walk(test_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        os.system(f'attrib -R "{file_path}"')
                    for dir in dirs:
                        dir_path = os.path.join(root, dir)
                        os.system(f'attrib -R "{dir_path}"')
            
            shutil.rmtree(test_dir)
            print(f"Test environment cleaned up: {test_dir.absolute()}")
        except Exception as e:
            print(f"Error cleaning up test environment: {e}")
            print("You may need to manually remove read-only attributes and delete the directory.")
    else:
        print("Test environment not found.")

def main():
    print("Ransomware Simulation Test Setup")
    print("=" * 40)
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
