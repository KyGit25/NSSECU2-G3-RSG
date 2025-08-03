RANSOMWARE SIMULATION TOOL - USER MANUAL

1. INTRODUCTION

The Ransomware Simulator Generator is an educational tool designed to demonstrate how ransomware operates in a controlled environment.

Key Features:
- Multiple encryption methods (RENAME, XOR, AES)
- Safe file processing with built-in protections
- Recording all operations in the log file
- Educational ransom note generation
- Complete file recovery capabilities
- Error handling for protected files

2. SAFETY AND LEGAL CONSIDERATIONS

CRITICAL WARNING: This tool is for educational use only in controlled laboratory environments.

DO NOT USE ON:
- Production systems or servers
- Personal computers with important data
- Any system containing critical business information
- Networks connected to production environments

AUTHORIZED USE ONLY:
- Dedicated lab machines
- Virtual machines in isolated environments
- Test directories created specifically for this exercise
- Educational institutions with proper supervision

Legal Notice: Users are fully responsible for ensuring appropriate use. Misuse of this tool may violate local, state, or federal laws.

3. SYSTEM REQUIREMENTS

Operating System:
- Windows 10 or later
- Kali Linux
- macOS 10.14 or later

Software Requirements:
- Python 3.7 or higher
- pip package manager

Required Python Libraries:
- cryptography (for AES encryption)
- pathlib (standard library)
- logging (standard library)
- os (standard library)

Hardware Requirements:
- Minimum 2GB RAM
- 100MB free disk space
- Standard file system permissions

4. INSTALLATION AND SETUP

Step 1: Install Python Dependencies
Open command prompt or terminal and run:
   pip install cryptography

Step 2: Download Tool Files
Ensure you have these files in your working directory:
- rsg.py (main application)
- test.py (test environment creator)
- manual.txt (this manual)

Step 3: Create Test Environment
Run the test setup script:
   python test.py

Select option 1 to create a test environment with sample files.

Step 4: Verify Installation
The tool will create a "ransomware_test" directory with various file types for testing.

5. USING THE TOOL

Starting the Application:
1. Open command prompt or terminal
2. Navigate to the tool directory
3. Run: python rsg.py
4. Read and acknowledge the safety warning
5. Type "I UNDERSTAND" to proceed

Operation Modes:

ENCRYPTION MODE (Simulate Attack):
1. Select option 1 when prompted
2. Choose encryption method (RENAME/XOR/AES)
3. Enter target directory path
4. Review file count and confirm operation
5. Save encryption key if prompted
6. Monitor progress and results

DECRYPTION MODE (File Recovery):
1. Select option 2 when prompted
2. Enter directory containing encrypted files
3. Choose the same encryption method used previously
4. Enter decryption key if required
5. Confirm recovery operation
6. Verify restored files

Directory Selection:
- Use absolute paths (e.g., C:\ransomware_test)
- Avoid system directories
- Recommended: Use test directories with "test", "lab", or "demo" in the name



