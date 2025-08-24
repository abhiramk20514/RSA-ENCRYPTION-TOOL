# 🔐 RSA Encryption Tool

A simple yet powerful RSA Encryption-Decryption tool built with Python and Tkinter. This project demonstrates how asymmetric encryption works and provides a GUI for secure message and file handling.


## 📌 Project Title
**Encryption Using RSA Algorithm**

## 👨‍💻 Developed By
**Kolluru Sai Abhiram**  
**Reg. No.: 23BCE20342**  
**VIT-AP University**


## 🎯 Objective

This project implements the RSA encryption technique using Python. The tool enables:

- Generation of RSA key pairs (public/private)
- Encryption and decryption of text
- File-based encryption and decryption
- GUI-based interaction for non-programmers


## 🧰 Requirements

- Python 3.8 or higher  
- pycryptodome

### 📦 Install Dependencies
```bash
pip install pycryptodome
```


## 🛠️ How to Run

### 🔗 Step 1: Clone the Repository
```bash
git clone https://github.com/abhiram342-vit/RSA-ENCRYPTION
cd RSA-ENCRYPTION
```

### ▶️ Step 2: Run the GUI
```bash
python rsa_gui.py
```


## 💡 Features

- 🔐 RSA Key Pair Generation (512-bit for demo)
- 📝 Text Encryption & Decryption
- 📂 File Encryption & Decryption (`.txt` ⇄ `.enc`)
- 💾 Save and Load Key files
- 🧼 Clear interface with a modern layout


## 🖼️ GUI Overview

- **Generate Keys** → Creates RSA key pair  
- **Save Keys** → Stores keys in `rsa_keys.json`  
- **Load Keys** → Loads saved keys  
- **Encrypt** → Encrypts the message  
- **Decrypt** → Decrypts the cipher  
- **Encrypt File** → Encrypts a `.txt` file  
- **Decrypt File** → Decrypts a `.enc` file  
- **Clear All** → Resets all input/output areas  


## 🔐 Manual Test (CLI)

Try this from Python shell:

```python
from rsa_core import generate_keys, encrypt, decrypt

pub, priv = generate_keys()
cipher = encrypt("Hello RSA", pub)
print("Encrypted:", cipher)
print("Decrypted:", decrypt(cipher, priv))
```


## ⚠️ Security Note

> This tool uses 512-bit RSA keys for demonstration.  
> For real-world use, RSA key sizes of **2048 bits or higher** are recommended.


## 📁 Project Structure

```
RSA-ENCRYPTION/
├── rsa_core.py           # Core RSA logic
├── rsa_gui.py            # Tkinter GUI interface
├── rsa_keys.json         # Sample key file (after saving)
├── README.md             # This file
├── project_documentation.pdf  # Detailed report
```


## 🌐 GitHub Repository

🔗 [https://github.com/abhiram342-vit/RSA-ENCRYPTION](https://github.com/abhiram342-vit/RSA-ENCRYPTION)


## ✅ Final Output

> A user-friendly RSA GUI that allows secure encryption and decryption of text and files.

## 👨‍🎓 Student Info

**Name:** Kolluru Sai Abhiram  
**Reg. No.:** 23BCE20342  
**University:** VIT-AP University


## 🙏 Thank You
