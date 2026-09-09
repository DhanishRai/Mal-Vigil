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