# Mal-Vigil

A lightweight background tool for Linux that watches your **Downloads** folder, checks newly downloaded executable files for malware using Machine Learning, and locks them before they can run.

---

## What Does This Project Do?

When you download files from the internet, you might accidentally double-click a dangerous program before checking it. 

**Mal-Vigil runs silently in the background to protect you:**
1. It detects any `.exe` or `.dll` file the second it lands in your `Downloads` folder.
2. It inspects the inside of the file without running it.
3. A trained Machine Learning model (LightGBM) checks if the file has patterns common in malware or ransomware.
4. If it looks dangerous, it immediately renames the file to end with `.isolated` (making it impossible to run by accident) and sends a notification to your desktop.

---

## How It Works (Simple Diagram)
File downloaded into ~/Downloads
│
▼
Mal-Vigil detects the file
│
▼
Inspects code patterns safely (Entropy, APIs, Headers)
│
▼
Machine Learning Model calculates Risk Score
│
┌───────┴───────┐
▼               ▼
Risk under 50%   Risk 50% or higher
[File is safe]   [Threat detected!]
│               │
│               ├── 1. Renames file to .isolated
│               └── 2. Pops up desktop notification
▼               ▼
Ready to use    File safely locked
---

## Key Features

* **Runs Automatically:** You do not need to open the app or scan files manually. It watches the folder 24/7.
* **Checks Without Running:** It scans files safely from the outside so no harmful code can execute during the check.
* **Safe Quarantine:** It doesn't delete your files. It only renames them to `.isolated`. If it's a file you trust, you can easily restore it.
* **Very Low RAM Usage:** Uses only about 25 MB of RAM, so it will never slow down your computer.
* **Runs 100% Locally:** None of your files or data are uploaded to the internet or any cloud server.

---

## Tech Stack

* **Language:** Python 3
* **Folder Monitoring:** `watchdog`
* **File Inspection:** `pefile`
* **Machine Learning:** `lightgbm`, `scikit-learn`, `numpy`
* **Desktop Alerts:** `notify-send` (Ubuntu desktop notifications)

---

## Folder Structure

```text
Mal-Vigil/
├── requirements.txt      # List of required Python packages
├── extractor.py          # Safely reads file patterns and features
├── train_model.py        # Trains the machine learning model
├── watcher.py            # Main background program that guards your folder
└── models/
    └── malware_lgbm.txt  # Saved trained model weights

    How to Install & Run


 1. Install System Requirements (Ubuntu / Linux)

    sudo apt update
     
    sudo apt install python3-pip python3-venv python-is-python3 libnotify-bin -y
 2. Download the Project

    git clone [https://github.com/DhanishRai/Mal-Vigil.git](https://github.com/DhanishRai/Mal-Vigil.git)
    cd Mal-Vigil

3. Set Up Python Virtual Environment
    
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt  

4. Train the Model (First Time Only)

    python train_model.py

5. Start the Guardian

   python watcher.py

   

