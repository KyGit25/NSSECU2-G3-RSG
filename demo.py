"""
Demo script for the Ransomware Simulator Generator
This script creates a test environment and demonstrates the tool's functionality.
"""

import os
import subprocess
import sys
from pathlib import Path

def create_test_environment():
    """Create a test directory with sample files."""
    print("📁 Creating test environment...")
    
    # Create test directory
    test_dir = Path("demo_test_lab")
    test_dir.mkdir(exist_ok=True)
    
    # Create sample files
    sample_files = {
        "document1.txt": "This is a sample text document for testing.\nIt contains multiple lines.\nThis is line 3.",
        "document2.txt": "Another sample file with different content.\nUsed for ransomware simulation testing.",
        "spreadsheet.csv": "Name,Age,City\nJohn,25,New York\nJane,30,Los Angeles\nBob,22,Chicago",
        "notes.md": "# Test Notes\n\nThis is a markdown file for testing.\n\n## Section 1\n- Item 1\n- Item 2",
        "config.json": '{\n  "application": "test",\n  "version": "1.0",\n  "debug": true\n}',
        "readme.txt": "Test file for ransomware simulation.\nThis file will be encrypted and then decrypted."
    }
    
    for filename, content in sample_files.items():
        file_path = test_dir / filename
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    print(f"✅ Created test directory: {test_dir}")
    print(f"📄 Created {len(sample_files)} sample files")
    return test_dir

def list_directory_contents(directory):
    """List contents of a directory."""
    print(f"\n📂 Contents of {directory}:")
    print("─" * 50)
    if directory.exists():
        for item in sorted(directory.iterdir()):
            if item.is_file():
                size = item.stat().st_size
                print(f"📄 {item.name} ({size} bytes)")
            else:
                print(f"📁 {item.name}/")
    else:
        print("Directory does not exist")
    print("─" * 50)

def demo_encryption():
    """Demonstrate the encryption functionality."""
    print("\n🔒 ENCRYPTION SIMULATION DEMO")
    print("=" * 60)
    
    test_dir = create_test_environment()
    
    print("\n📋 Before encryption:")
    list_directory_contents(test_dir)
    
    print("\n⚠️ The tool will now ask for confirmation.")
    print("⚠️ You need to type 'YES' and then 'CONFIRM' to proceed.")
    print("\n🔒 Running encryption simulation...")
    
    # Note: This is just showing the command - actual execution requires user input
    encryption_command = f'python testing.py --encrypt "{test_dir}"'
    print(f"Command to run: {encryption_command}")
    print("\n⚠️ To run this demo manually, execute the command above.")

def demo_decryption():
    """Demonstrate the decryption functionality."""
    print("\n🔓 DECRYPTION SIMULATION DEMO")
    print("=" * 60)
    
    test_dir = Path("demo_test_lab")
    
    if test_dir.exists():
        print("\n📋 Before decryption:")
        list_directory_contents(test_dir)
        
        decryption_command = f'python testing.py --decrypt "{test_dir}"'
        print(f"\nCommand to run: {decryption_command}")
        print("\n⚠️ To run this demo manually, execute the command above.")
    else:
        print("❌ Test directory not found. Run encryption demo first.")

def cleanup_demo():
    """Clean up the demo environment."""
    print("\n🧹 CLEANUP")
    print("=" * 60)
    
    import shutil
    test_dir = Path("demo_test_lab")
    
    if test_dir.exists():
        shutil.rmtree(test_dir)
        print(f"✅ Removed test directory: {test_dir}")
    
    # Clean up log files
    log_files = ["ransomware_simulation.log", "processed_files.json", "README_RANSOM.txt"]
    for log_file in log_files:
        if Path(log_file).exists():
            Path(log_file).unlink()
            print(f"✅ Removed log file: {log_file}")

def main():
    """Main demo function."""
    print("🎯 RANSOMWARE SIMULATOR GENERATOR - DEMO")
    print("=" * 60)
    print("This demo shows how to use the educational ransomware simulator.")
    print("⚠️ This tool is for EDUCATIONAL PURPOSES ONLY!")
    print("=" * 60)
    
    while True:
        print("\nChoose an option:")
        print("1. 🔒 Demo encryption simulation setup")
        print("2. 🔓 Demo decryption simulation setup")
        print("3. 📋 Show current test directory contents")
        print("4. 🧹 Cleanup demo environment")
        print("5. ❌ Exit")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == "1":
            demo_encryption()
        elif choice == "2":
            demo_decryption()
        elif choice == "3":
            test_dir = Path("demo_test_lab")
            list_directory_contents(test_dir)
        elif choice == "4":
            cleanup_demo()
        elif choice == "5":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
