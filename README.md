# 🔐 Basic Hash Cracker (Educational Project)

A Python-based educational tool for understanding how password hashes work and demonstrating the vulnerability of weak passwords to dictionary attacks.

![Hash Cracker Screenshot](https://github.com/username/hash-cracker/raw/main/screenshots/hash_cracker_demo.png)

## 📚 Educational Purpose

This project was created for educational purposes to demonstrate:

1. **How password hashing works** (MD5, SHA1, SHA256, SHA512)
2. **Why strong passwords are essential** for security
3. **How dictionary attacks work** against password hashes
4. **The importance of salt** in password storage (by showing what happens without it)

> ⚠️ **Important:** This tool should only be used for educational purposes or on your own systems. Unauthorized attempts to crack passwords on systems you don't own is illegal and unethical.

## 🔍 What is Password Hashing?

Password hashing is the process of transforming a password into a fixed-length string of characters using a one-way mathematical function. When implemented correctly, hashes:

- Cannot be reversed to reveal the original password
- Will always produce the same output for a given input
- Will produce dramatically different outputs even for similar inputs

Common hashing algorithms include MD5, SHA-1, SHA-256, and SHA-512, with newer algorithms generally providing stronger security.

## ⚡ Features

- **Multiple Hash Algorithms**: Supports MD5, SHA-1, SHA-256, and SHA-512
- **Command Line Interface**: For automation and scripting
- **Modern GUI Interface**: User-friendly design with real-time progress tracking
- **Hash Generation**: Create hashes for testing purposes
- **Progress Reporting**: See cracking progress in real-time
- **Cross-platform**: Works on Windows, macOS, and Linux

## 🛠️ How It Works

### The Basic Process

1. **Input**: The program takes a hash value and a wordlist file
2. **Processing**: Each word from the wordlist is:
   - Read from the file
   - Hashed using the specified algorithm
   - Compared to the target hash
3. **Output**: If a match is found, the original password is displayed

### Dictionary Attack Explained

A dictionary attack is a technique where an attacker uses a list of common words, phrases, and previously leaked passwords to try to find a match for a password hash. This approach is effective because:

1. Many people use simple, common passwords
2. People often reuse passwords across multiple sites
3. Without additional security measures (like salting), identical passwords always produce the same hash

The effectiveness of dictionary attacks is why password complexity requirements and unique password recommendations exist.

## 📋 Requirements

- Python 3.6+
- For GUI: `customtkinter` library (automatically prompts for installation)

## 🚀 Installation

1. Clone this repository:
   ```
   git clone https://github.com/username/hash-cracker.git
   cd hash-cracker
   ```

2. Install requirements (for GUI version):
   ```
   pip install customtkinter
   ```

## 💻 Usage

### Command Line Version

```bash
python hash_cracker.py <hash_to_crack> -a <algorithm> -w <wordlist_path>
```

Parameters:
- `hash_to_crack`: The hash value you want to crack
- `-a, --algorithm`: Hash algorithm (md5, sha1, sha256, sha512)
- `-w, --wordlist`: Path to wordlist file (default: wordlist.txt)
- `--generate`: Generate a hash for a given password instead of cracking

Examples:
```bash
# Crack an MD5 hash
python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 -a md5

# Generate an SHA-256 hash for "password"
python hash_cracker.py password --generate -a sha256
```

### GUI Version

```bash
python hash_cracker_gui.py
```

The GUI provides an intuitive interface:
1. Enter the hash to crack
2. Select the hashing algorithm
3. Browse for a wordlist file
4. Click "Start Cracking"

You can also generate hashes for testing using the "Generate Hash" button.

## 📝 Creating a Wordlist

For educational purposes, you can create a small wordlist containing common passwords:

1. Create a text file (e.g., `wordlist.txt`)
2. Add one password per line, such as:
   ```
   password
   123456
   qwerty
   admin
   welcome
   letmein
   ```

For research purposes, larger wordlists containing millions of previously leaked passwords are available online, but always ensure you're downloading from legal sources.

## 🔒 Security Best Practices (What This Tool Demonstrates)

Through using this tool, you'll learn important password security concepts:

1. **Use Strong Passwords**: Common words are quickly cracked
2. **Password Complexity Matters**: Longer passwords with mixed characters resist these attacks
3. **Each Site Needs a Unique Password**: Reusing passwords is dangerous when breaches occur
4. **Modern Hashing Is Essential**: Legacy algorithms like MD5 are too fast, making attacks easier
5. **Salt Your Hashes**: Adding random data to each hash prevents attacking multiple hashes simultaneously
6. **Use Password Managers**: They help create and store strong, unique passwords

## 🧪 Technical Details

### Supported Hash Algorithms

| Algorithm | Output Length | Security Status |
|-----------|---------------|----------------|
| MD5       | 128 bits      | Broken (not recommended) |
| SHA-1     | 160 bits      | Vulnerable (not recommended) |
| SHA-256   | 256 bits      | Strong |
| SHA-512   | 512 bits      | Very strong |

### Limitations of Simple Hashing

This tool demonstrates why modern password storage uses:
- **Salt**: Random data added to each password before hashing
- **Slow Hashing**: Algorithms like bcrypt that are deliberately time-consuming
- **Multiple Iterations**: Repeated hashing to increase computation time

Without these protections, a simple dictionary attack can be devastatingly effective.

## 🤔 Understanding the Results

When you use this tool, you'll observe:
- Common passwords are cracked almost instantly
- Complex passwords may resist basic dictionary attacks
- Large wordlists increase success rates dramatically
- Faster algorithms (MD5) are more vulnerable than slower ones

These observations highlight why proper password storage by developers and good password habits by users are critical security practices.

## 📊 Learning Exercises

1. **Speed Comparison**: Time how long it takes to crack the same password with different algorithms
2. **Password Strength Test**: Create hashes for passwords of varying complexity and try to crack them
3. **Wordlist Effectiveness**: Compare crack success rates with different wordlists
4. **Salt Implementation**: Try adding your own "salt" to passwords before hashing and observe the effect

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- This project is for educational purposes only
- Created to demonstrate password security concepts
- Inspired by cybersecurity education needs
