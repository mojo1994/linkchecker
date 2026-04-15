# linkchecker

A "link checker" code script written in Python that scans for vulnerabilities and malware in website links using the VirusTotal API. Use for learning ethical hacking.

> **ATTENTION:** You must create a free account at [VirusTotal](https://www.virustotal.com/) to get an API key. After obtaining your key, open `linkcheck.py` and set your key in the `API_KEY` variable at the top of the file.

## How to Use

To use in Termux or a Linux terminal, follow these steps:

### 1 - Update and upgrade your package manager

**Termux:**
```bash
pkg update && pkg upgrade
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt update && sudo apt upgrade
```

### 2 - Install Python

**Termux:**
```bash
pkg install python
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install python3 python3-pip
```

### 3 - Install Python dependencies

```bash
pip install colorama requests
```

### 4 - Clone the repository

If you don't have `git` installed:

**Termux:**
```bash
pkg install git
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install git
```

Then clone the repository and enter the project directory:

```bash
git clone https://github.com/mojo1994/linkchecker
cd linkchecker
```

### 5 - Run the script

```bash
python linkcheck.py
```

You can also use the following flags:

```bash
python linkcheck.py -h    # Show help
python linkcheck.py -L    # List URL history
```

