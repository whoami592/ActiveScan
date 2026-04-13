


<img width="1316" height="674" alt="sabaz ali khan (2)" src="https://github.com/user-attachments/assets/78ba1f59-87e7-4fb9-a77d-9a15b9a9a9c8" />




# ActiveScan
ActiveScan provides a fast and reliable way to scan networks and identify active devices. Built with simplicity and performance in mind, it helps users perform network reconnaissance and security assessments in an ethical and controlled environment.



✨ Features

🔍 Fast Host Discovery

🌐 Network and IP Range Scanning

📡 Open Port Detection

⚡ Multi-threaded Scanning for High Performance

🖥️ User-Friendly Command-Line Interface


📊 Real-Time Scan Results

📁 Export Results to File

🔒 Designed for Ethical Hacking and Educational Purposes

🐍 Built Using Pure Python



🛠️ Technologies Used

Python 3

Socket Library

Threading

IPaddress Module

Argparse

Datetime


Project Structure

ActiveScan/
│── activescan.py
│── requirements.txt
│── README.md
│── LICENSE
│── .gitignore
└── output/
    └── scan_results.txt


    Installation

1️⃣ Clone the Repository

git clone https://github.com/whoami592/ActiveScan.git

cd ActiveScan

2️⃣ Install Dependencies

pip install -r requirements.txt


Usage

Basic Scan

python activescan.py -t 192.168.1.1

Scan a Range of IP Addresses

python activescan.py -t 192.168.1.1-192.168.1.50


Full Network Scan

python activescan.py -t 192.168.1.0/24


📸 Sample Output

========================================
        ActiveScan Network Scanner
        Coded by Mr. Sabaz Ali Khan
========================================


Target: 192.168.1.1

Scanning started at: 2026-04-13


[+] Host is Active

[+] Open Ports:
    
    - Port 22 (SSH)
    
    - Port 80 (HTTP)
    
    - Port 443 (HTTPS)

Scan completed successfully.

🔒 Disclaimer

This tool is developed strictly for educational and ethical purposes. Unauthorized scanning of networks without permission is illegal. The developer is not responsible for any misuse or damage caused by this tool.


👨‍💻 Author

Mr. Sabaz Ali Khan

🔹 Python Developer | Cybersecurity Enthusiast | Ethical Hacker

🌐 GitHub: https://github.com/whoami592

📧 Email: Sabazali236@gmail.com

⭐ Support


If you like this project, please consider giving it a star ⭐ on GitHub to support future development.



