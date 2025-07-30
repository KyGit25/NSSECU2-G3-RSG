# NSSECU2-G3-RSG - Ransomware Simulator Generator

**Group 3 - Educational Ransomware Simulation Tool**

## ⚠️ **CRITICAL WARNING** ⚠️

**THIS TOOL IS FOR EDUCATIONAL PURPOSES ONLY**

- 🚫 **DO NOT USE ON PRODUCTION SYSTEMS**
- 🚫 **DO NOT USE ON PERSONAL COMPUTERS**
- ✅ **USE ONLY IN ISOLATED LAB ENVIRONMENTS**
- ✅ **USE ONLY IN VIRTUAL MACHINES**

## 📋 Project Overview

This project develops a ransomware simulation tool that operates safely within a lab environment. The tool simulates ransomware behavior by encrypting files in a controlled manner, allowing students to understand ransomware mechanics and explore recovery techniques without causing actual harm.

## 🎯 Learning Objectives

- Understand how ransomware traverses and affects file systems
- Learn about encryption techniques used by malicious actors
- Practice incident response and recovery procedures
- Develop awareness of cybersecurity threats and prevention strategies

## ✨ Features

### Core Functionality
- ✅ **Recursive Directory Scanning**: Safely scans user-specified directories
- ✅ **File Encryption Simulation**: Encrypts files using AES-256 (Fernet) encryption
- ✅ **File Renaming**: Adds `.locked` extension to encrypted files
- ✅ **Ransom Note Generation**: Creates educational ransom note with recovery instructions
- ✅ **Safe Decryption**: Provides complete recovery functionality
- ✅ **Comprehensive Logging**: Maintains detailed logs of all operations
- ✅ **Error Handling**: Gracefully handles protected and system files
- ✅ **Safety Checks**: Prevents execution on dangerous system directories

### Security Features
- 🛡️ **Educational Warnings**: Clear warnings before execution
- 🛡️ **User Confirmation**: Multiple confirmation steps required
- 🛡️ **System Protection**: Automatic detection and prevention of system directory targeting
- 🛡️ **Fixed Encryption Key**: Uses fixed key for educational recovery (never use in production)

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- Virtual machine or isolated lab environment

### Setup
1. Clone or download this repository
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

### Command Line Interface

#### Encryption Simulation
```bash
# Encrypt files in a specific directory
python testing.py --encrypt "C:\temp\test_folder"

# Or use short form
python testing.py -e "./test_directory"
```

#### Decryption Simulation
```bash
# Decrypt files in a specific directory
python testing.py --decrypt "C:\temp\test_folder"

# Or use short form
python testing.py -d "./test_directory"
```

### Example Workflow

1. **Prepare Test Environment**
   ```bash
   # Create a test directory with sample files
   mkdir test_lab
   cd test_lab
   echo "This is a test file" > document1.txt
   echo "Another test file" > document2.txt
   ```

2. **Run Encryption Simulation**
   ```bash
   python testing.py --encrypt "./test_lab"
   ```

3. **Observe Results**
   - Files are renamed with `.locked` extension
   - File contents are encrypted
   - `README_RANSOM.txt` is created with recovery instructions
   - Operations are logged in `ransomware_simulation.log`

4. **Run Decryption Simulation**
   ```bash
   python testing.py --decrypt "./test_lab"
   ```

5. **Verify Recovery**
   - Files are restored to original names
   - File contents are decrypted
   - Ransom note is removed

## 📁 Project Structure

```
NSSECU2-G3-RSG/
├── testing.py                 # Main ransomware simulator
├── requirements.txt           # Python dependencies
├── README.md                 # This documentation
├── ransomware_simulation.log # Operation logs (generated)
├── processed_files.json     # File tracking (generated)
└── README_RANSOM.txt        # Ransom note (generated during simulation)
```

## 🔧 Technical Details

### Encryption Method
- **Algorithm**: AES-256 encryption via Fernet (cryptography library)
- **Key Management**: Fixed key for educational purposes
- **File Processing**: Content encryption + filename extension modification

### Safety Mechanisms
- **Directory Validation**: Prevents targeting of system directories
- **User Confirmation**: Multiple confirmation steps required
- **Error Handling**: Graceful handling of protected files
- **Logging**: Comprehensive operation tracking

### Protected Directories
The tool automatically prevents execution on dangerous system paths:
- Windows: `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`
- Linux/Unix: `/usr`, `/bin`, `/sbin`, `/etc`, `/var`, `/home`

## 📊 Logging and Monitoring

### Log Files Generated
1. **`ransomware_simulation.log`**: Detailed operation logs
2. **`processed_files.json`**: JSON record of all processed files with metadata

### Log Information Includes
- Timestamp of operations
- File paths (original and encrypted)
- Success/failure status
- Error messages for failed operations
- Encryption/decryption actions

## 🛡️ Security Considerations

### Educational Context
- Uses fixed encryption key (educational recovery guarantee)
- Includes comprehensive warnings and confirmations
- Designed for controlled lab environments only

### Real-World Ransomware Differences
- Real ransomware uses random/unknown keys
- Real ransomware targets system files and critical data
- Real ransomware often includes network communication
- Real ransomware may include anti-analysis techniques

## 🔬 Educational Exercises

### Suggested Lab Activities

1. **Basic Simulation**
   - Run encryption on test directory
   - Analyze file system changes
   - Practice recovery procedures

2. **Incident Response**
   - Simulate discovery of "ransomware attack"
   - Practice documentation and reporting
   - Test backup recovery procedures

3. **Prevention Analysis**
   - Discuss how the attack could have been prevented
   - Implement monitoring solutions
   - Test backup integrity

4. **Forensic Analysis**
   - Examine log files
   - Track file modifications
   - Analyze attack patterns

## 🆘 Troubleshooting

### Common Issues

**Issue**: Permission errors when accessing files
**Solution**: Ensure you have appropriate permissions and are not targeting system files

**Issue**: Encryption fails on some files
**Solution**: Check logs for specific error messages; some files may be in use by other processes

**Issue**: Decryption doesn't work
**Solution**: Ensure you're running decryption on the same directory where encryption was performed

### Recovery Options

If normal decryption fails:
1. Check `processed_files.json` for file tracking information
2. Review `ransomware_simulation.log` for error details
3. Manually restore from backups if available

## 👥 Contributing

This is an educational project for NSSECU02. Group 3 members:
- [Add team member names here]

## 📚 References and Further Reading

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Incident Response Guide](https://www.sans.org/white-papers/incident-response/)
- [Cryptography Library Documentation](https://cryptography.io/)

## 📄 License

This project is for educational use only as part of the NSSECU02 course. Not for commercial or malicious use.

## 🔗 Support

For questions related to this educational tool:
1. Check the troubleshooting section above
2. Review the comprehensive logging output
3. Consult with course instructors

---

**Remember: This tool is designed to educate about cybersecurity threats. Always use responsibly and only in appropriate educational environments.**