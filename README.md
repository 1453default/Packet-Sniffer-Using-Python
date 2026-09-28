  # Packet Sniffer Using Python

 A Python-based packet sniffing and network traffic analysis tool built with **Scapy**.

 The project can capture live network traffic or analyze an existing `.pcap` file. It identifies common network protocols, summarizes conversations, performs a small set of transparent security heuristics, and can export a privacy-conscious report in JSON or CSV format.

 > **Authorization notice:** Only capture or analyze traffic on networks, systems, and packet captures that you own or are explicitly authorized to inspect.

---

 ## 1\. Features

 - Live packet capture
- Offline `.pcap` analysis
- TCP, UDP, ICMP, and IP protocol identification
- DNS query detection
- HTTP request detection
- Common service/port identification
- Traffic statistics
- Conversation/flow summaries
- Basic security heuristics
- Detection of traffic involving:
  - FTP
  - Telnet
  - SMB
- Large packet detection
- High-volume host detection
- Basic possible service-probing detection
- Colored terminal interface using Rich
- JSON report export
- CSV report export
- Optional saving of raw packet captures
- IP pseudonymization in exported reports

---

 # 2\. How the Project Works

 The tool follows this general workflow:

```
                ┌──────────────────┐
                │ Network Interface│
                └────────┬─────────┘
                         │
                         ▼
                 ┌───────────────┐
                 │ Scapy Capture │
                 └───────┬───────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Packet Analysis  │
                └────────┬─────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
       Protocols      DNS/HTTP       Traffic
       Detection      Detection      Statistics
          │              │              │
          └──────────────┼──────────────┘
                         ▼
                ┌──────────────────┐
                │ Security Rules   │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │ Terminal Report  │
                └────────┬─────────┘
                         │
                    ┌────┴────┐
                    ▼         ▼
                  JSON       CSV
                 Report     Report
```

---

 # 3\. Requirements

 ## Software Requirements

 ### Linux / Kali Linux

 - Python 3
- pip
- Python virtual environment support
- Scapy
- Rich
- Appropriate permissions for live packet capture

 ### Windows

 - Python 3
- pip
- Python virtual environment support
- Scapy
- Rich
- Npcap for live packet capture

---

 # 4\. Project Structure

 After downloading or cloning the project, the directory should look similar to:

```
Packet-Sniffer-Using-Python/
│
├── capture.pcap
├── README.md
├── requirements.txt
├── sniffer.py
│
└── venv/
```

 ### Files

 | File | Description |
| --- | --- |
| `sniffer.py` | Main packet sniffer and analyzer |
| `requirements.txt` | Python dependencies |
| `capture.pcap` | Example packet capture |
| `README.md` | Project documentation |
| `venv/` | Python virtual environment created locally |

---

 # 5\. Installation on Kali Linux / Linux

 ## Step 1 — Open a terminal

 Navigate to the location where you want to keep the project.

 For example:

```
cd ~
```

---

 ## Step 2 — Clone or download the project

 If the project is hosted on GitHub:

```
git clone <YOUR-REPOSITORY-URL>
```

 Then enter the project:

```
cd Packet-Sniffer-Using-Python
```

 If you already downloaded the project, simply enter its directory:

```
cd ~/Packet-Sniffer-Using-Python
```

---

 ## Step 3 — Check Python

 Run:

```
python3 --version
```

 You should see a Python 3 version.

 Also check pip:

```
python3 -m pip --version
```

---

 ## Step 4 — Create a virtual environment

 Run:

```
python3 -m venv venv
```

 If your Linux distribution reports that the `venv` module is missing, install the appropriate package.

 On Debian/Kali-based systems:

```
sudo apt update
sudo apt install python3-venv
```

 Then create the environment again:

```
python3 -m venv venv
```

---

 ## Step 5 — Activate the virtual environment

```
source venv/bin/activate
```

 Your terminal prompt should now contain:

```
(venv)
```

 For example:

```
(venv) user@kali:~/Packet-Sniffer-Using-Python$
```

---

 ## Step 6 — Install dependencies

 Run:

```
pip install -r requirements.txt
```

 If `requirements.txt` does not contain Rich, install it with:

```
pip install rich
```

 You can verify the installation:

```
pip show scapy
pip show rich
```

---

 # 6\. Installation on Windows

 ## Step 1 — Install Python

 Install Python 3 from the official Python website:

 https://www.python.org/downloads/

 During installation, make sure:

```
Add Python to PATH
```

 is enabled.

 After installation, open **PowerShell** or **Command Prompt**.

 Verify:

```
python --version
```

 and:

```
pip --version
```

---

 # 7\. Install Npcap on Windows

 Live packet capture on Windows generally requires a packet-capture driver such as **Npcap**.

 Download and install Npcap from:

 https://npcap.com/

 During installation, use the default options unless you have a specific configuration requirement.

 After installing Npcap, restart your terminal.

 > Offline `.pcap` analysis does not require live packet capture. If you only want to analyze `capture.pcap`, you can generally skip the Npcap setup.

---

 # 8\. Get the Project on Windows

 If using Git:

```
git clone <YOUR-REPOSITORY-URL>
```

 Then:

```
cd Packet-Sniffer-Using-Python
```

 If you downloaded a ZIP file, extract it and navigate into the extracted directory.

 For example:

```
cd C:\Users\YourName\Downloads\Packet-Sniffer-Using-Python
```

---

 # 9\. Create a Virtual Environment on Windows

 Run:

```
python -m venv venv
```

 Activate it using PowerShell:

```
.\venv\Scripts\Activate.ps1
```

 You should see:

```
(venv)
```

 in your terminal prompt.

 ### If PowerShell blocks activation

 You may receive an execution-policy error.

 You can use Command Prompt instead:

```
venv\Scripts\activate.bat
```

 Or, if permitted by your system policy, PowerShell can be configured to allow local scripts.

---

 # 10\. Install Python Dependencies on Windows

 With the virtual environment activated:

```
python -m pip install --upgrade pip
```

 Then:

```
pip install -r requirements.txt
```

 If Rich is not included in `requirements.txt`:

```
pip install rich
```

 Verify:

```
pip show scapy
pip show rich
```

---

 # 11\. First Test — Analyze the Included PCAP

 The easiest way to test the project is to analyze the included `capture.pcap`.

 ### Linux / Kali

```
python3 sniffer.py --read-pcap capture.pcap
```

 ### Windows

```
python sniffer.py --read-pcap capture.pcap
```

 This does not require live packet capture.

 The program will analyze the saved packets and display:

 - Packet information
- Protocol statistics
- Traffic volume
- Conversations
- Security heuristic findings

---

 # 12\. Display Help

 To see all available options:

 ### Linux / Kali

```
python3 sniffer.py --help
```

 ### Windows

```
python sniffer.py --help
```

 The available options are:

```
--read-pcap READ_PCAP
--interface INTERFACE
--filter CAPTURE_FILTER
--count COUNT
--timeout TIMEOUT
--save-pcap SAVE_PCAP
--export EXPORT
```

---

 # 13\. Live Packet Capture

 ## Linux / Kali

 Live packet capture normally requires elevated privileges.

 Run:

```
sudo python3 sniffer.py
```

 The default configuration captures:

```
Maximum packets: 100
Timeout: 30 seconds
```

---

 ## Windows

 Open **PowerShell as Administrator**.

 Navigate to the project:

```
cd C:\path\to\Packet-Sniffer-Using-Python
```

 Activate the virtual environment:

```
.\venv\Scripts\Activate.ps1
```

 Then run:

```
python sniffer.py
```

 Npcap must be installed for live capture.

---

 # 14\. Capture a Specific Number of Packets

 For example, capture 10 packets:

 ### Linux

```
sudo python3 sniffer.py --count 10
```

 ### Windows

```
python sniffer.py --count 10
```

 You can also specify a timeout:

```
sudo python3 sniffer.py --count 10 --timeout 15
```

 This captures up to 10 packets or stops after 15 seconds, depending on which condition occurs first.

---

 # 15\. Select a Network Interface

 If multiple interfaces exist, specify one using:

```
sudo python3 sniffer.py --interface eth0
```

 Example interfaces may include:

```
eth0
wlan0
enp0s3
```

 The actual interface names depend on your system.

 To see interfaces on Linux, you can use:

```
ip link
```

 or:

```
ip addr
```

 On Windows, available interfaces depend on your Npcap installation and Scapy configuration.

---

 # 16\. Capture Only Specific Traffic

 The program supports BPF capture filters.

 For example, TCP traffic:

```
sudo python3 sniffer.py --filter "tcp"
```

 HTTP traffic:

```
sudo python3 sniffer.py --filter "tcp port 80"
```

 HTTPS traffic:

```
sudo python3 sniffer.py --filter "tcp port 443"
```

 DNS traffic:

```
sudo python3 sniffer.py --filter "udp port 53"
```

 You can combine a filter with a packet limit:

```
sudo python3 sniffer.py --count 20 --filter "tcp port 443"
```

 > Capture filters are applied by the underlying packet-capture system. Filter support can vary depending on the operating system and capture backend.

---

 # 17\. Analyze a PCAP File

 You can analyze any authorized PCAP file:

```
python3 sniffer.py --read-pcap example.pcap
```

 On Windows:

```
python sniffer.py --read-pcap example.pcap
```

 For example:

```
python3 sniffer.py --read-pcap capture.pcap
```

 No live network capture is required.

---

 # 18\. Export a JSON Report

 To generate a JSON report:

```
python3 sniffer.py \
    --read-pcap capture.pcap \
    --export report.json
```

 On Windows:

```
python sniffer.py --read-pcap capture.pcap --export report.json
```

 The generated report contains metadata such as:

 - Timestamp
- Pseudonymous source
- Pseudonymous destination
- Protocol
- Source port
- Destination port
- Packet size
- Conversations
- Security findings

 Raw IP addresses are pseudonymized in the exported report.

---

 # 19\. Export a CSV Report

 Use:

```
python3 sniffer.py \
    --read-pcap capture.pcap \
    --export report.csv
```

 Windows:

```
python sniffer.py --read-pcap capture.pcap --export report.csv
```

 The resulting CSV can be opened with:

 - Microsoft Excel
- LibreOffice Calc
- Google Sheets
- Python/pandas
- Other spreadsheet applications

---

 # 20\. Save a Raw PCAP Capture

 Live captures can optionally be saved:

```
sudo python3 sniffer.py \
    --count 100 \
    --timeout 30 \
    --save-pcap my_capture.pcap
```

 The resulting file can later be analyzed:

```
python3 sniffer.py --read-pcap my_capture.pcap
```

 > Raw PCAP files can contain sensitive network information. Store and share them carefully.

---

 # 21\. Example Commands

 ## Quick PCAP analysis

```
python3 sniffer.py --read-pcap capture.pcap
```

 ## Capture 10 packets

```
sudo python3 sniffer.py --count 10
```

 ## Capture for 15 seconds

```
sudo python3 sniffer.py --timeout 15
```

 ## Capture 20 HTTPS packets

```
sudo python3 sniffer.py \
    --count 20 \
    --filter "tcp port 443"
```

 ## Analyze and export JSON

```
python3 sniffer.py \
    --read-pcap capture.pcap \
    --export report.json
```

 ## Analyze and export CSV

```
python3 sniffer.py \
    --read-pcap capture.pcap \
    --export report.csv
```

 ## Capture and save PCAP

```
sudo python3 sniffer.py \
    --count 100 \
    --timeout 30 \
    --save-pcap network_capture.pcap
```

---

 # 22\. Understanding the Output

 The terminal interface provides several sections.

 ## Packet Table

 The packet table displays information such as:

```
Packet number
Source IP
Destination IP
Protocol
Packet size
Packet details
```

 Example:

```
#    Source       Destination       Protocol    Bytes
1    10.0.2.15    172.64.155.209    HTTPS       7354
2    172.64.155.209 10.0.2.15       TCP           60
```

---

 ## Traffic Overview

 The overview summarizes:

```
IP packets analyzed
Total traffic
TCP packets
UDP packets
ICMP packets
Number of conversations
```

---

 ## Security Findings

 The project uses simple, transparent heuristics.

 Possible findings include:

 ### HIGH

 Traffic involving Telnet may be marked HIGH because Telnet commonly transmits communication without modern encryption.

 ### MEDIUM

 Traffic involving services such as FTP or SMB may be flagged according to the configured rules.

 ### LOW

 Large packets or unusually high packet volume within the short capture window may be reported.

 These findings are **heuristic indicators, not proof of malicious activity**.

 For example:

```
[LOW] Large IP packet observed
```

 does not by itself mean that the packet is malicious.

---

 # 23\. Privacy and Report Export

 The exported JSON and CSV reports use pseudonymous host identifiers.

 For example, instead of exporting:

```
192.168.1.10
```

 the report may contain:

```
host-a1b2c3d4
```

 This is intended to reduce unnecessary exposure of IP addresses when sharing reports.

 The exported report does not intentionally include:

 - Packet payloads
- Raw IP addresses
- DNS names
- HTTP paths

 However, raw PCAP files are different. A PCAP may contain sensitive information depending on how it was captured.

---

 # 24\. Troubleshooting

 ## `dpkg was interrupted`

 On Kali/Debian systems, you may see:

```
Error: dpkg was interrupted
```

 Run:

```
sudo dpkg --configure -a
```

 Then:

```
sudo apt --fix-broken install
```

 After the package manager is repaired:

```
sudo apt update
```

 and install the required Python packages if necessary.

---

 ## `No module named scapy`

 Activate your virtual environment:

```
source venv/bin/activate
```

 Then:

```
pip install -r requirements.txt
```

---

 ## `No module named rich`

 Install Rich:

```
pip install rich
```

---

 ## Linux live capture permission error

 Try running:

```
sudo python3 sniffer.py
```

 Make sure you are capturing traffic on a network/interface you are authorized to inspect.

---

 ## Windows live capture does not work

 Check that:

 1. Python is installed.
2. Scapy is installed.
3. Npcap is installed.
4. PowerShell/Command Prompt has the required privileges.
5. The correct network interface is selected.

 Test Python:

```
python --version
```

 Test Scapy:

```
python -c "import scapy; print('Scapy OK')"
```

---

 ## Virtual environment activation does not work

 ### Linux

 Make sure you are inside the project directory:

```
cd ~/Packet-Sniffer-Using-Python
```

 Then:

```
source venv/bin/activate
```

 ### Windows PowerShell

```
cd C:\path\to\Packet-Sniffer-Using-Python
.\venv\Scripts\Activate.ps1
```

 ### Windows Command Prompt

```
cd C:\path\to\Packet-Sniffer-Using-Python
venv\Scripts\activate.bat
```

---

 # 25\. Deactivating the Virtual Environment

 When finished:

 ### Linux / Windows

```
deactivate
```

 The `(venv)` indicator should disappear from the terminal prompt.

---

 # 26\. Recommended First Run

 If you are a new user, the easiest way to verify the project is:

 ### Linux / Kali

```
cd ~/Packet-Sniffer-Using-Python
source venv/bin/activate
pip install -r requirements.txt
python3 sniffer.py --read-pcap capture.pcap
```

 ### Windows

```
cd C:\path\to\Packet-Sniffer-Using-Python
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python sniffer.py --read-pcap capture.pcap
```

 This uses the included PCAP and avoids the complexity of live packet capture.

---

 # 27\. Security and Ethical Use

 This project is intended for:

 - Cybersecurity education
- Network troubleshooting
- Personal lab environments
- Authorized security testing
- Analysis of packet captures that you are permitted to inspect

 Do not use the tool to intercept, monitor, or analyze network traffic without appropriate authorization.

 When working in a lab, use traffic generated by your own virtual machines or systems.

---

 # 28\. Limitations

 This project is designed as an educational packet-analysis tool rather than a full enterprise network monitoring platform.

 Important limitations include:

 - Security findings are based on simple heuristics.
- A finding does not automatically indicate an attack.
- Encrypted traffic limits application-level visibility.
- Packet classification is not equivalent to deep protocol analysis.
- The tool does not replace IDS/IPS systems.
- The tool does not perform comprehensive malware detection.
- The tool does not determine whether a host is compromised.
- Results depend on the packets available in the capture.
- Large or high-volume captures may produce substantial terminal output.

---

 # 29\. Technologies Used

 ### Python

 Main programming language.

 ### Scapy

 Used for:

 - Packet capture
- PCAP reading
- Packet parsing
- Packet writing
- Protocol inspection

 ### Rich

 Used for:

 - Colored terminal output
- Tables
- Panels
- Structured CLI presentation

---

 # 30\. Learning Objectives

 This project demonstrates practical concepts including:

 - Network packet structure
- IP addressing
- TCP and UDP
- Network ports
- DNS
- HTTP/HTTPS
- Packet capture
- PCAP files
- Network conversations
- Traffic statistics
- Basic security heuristics
- Python virtual environments
- Command-line interfaces
- JSON/CSV report generation
- Privacy-conscious security reporting

---

 # 31\. Future Improvements

 Potential future improvements include:

 - Real-time packet counters
- Protocol distribution charts
- Bandwidth graphs
- Interface auto-detection
- Better IPv6 support
- More protocol decoders
- Configurable security rules
- GeoIP enrichment
- Web-based dashboard
- Interactive filtering
- HTML report generation
- Automatic report timestamps
- Exportable graphical reports

---

 # 32\. License

 Add your chosen license here.

 For example:

```
MIT License
```

 If this project is intended for public distribution, include the complete license text in a separate `LICENSE` file.

---

 # 33\. Quick Reference

 | Task | Linux / Kali | Windows |
| --- | --- | --- |
| Check Python | `python3 --version` | `python --version` |
| Create venv | `python3 -m venv venv` | `python -m venv venv` |
| Activate venv | `source venv/bin/activate` | `.\venv\Scripts\Activate.ps1` |
| Install packages | `pip install -r requirements.txt` | `pip install -r requirements.txt` |
| Show help | `python3 sniffer.py --help` | `python sniffer.py --help` |
| Analyze PCAP | `python3 sniffer.py --read-pcap capture.pcap` | `python sniffer.py --read-pcap capture.pcap` |
| Live capture | `sudo python3 sniffer.py` | Run PowerShell as Administrator |
| Export JSON | `--export report.json` | `--export report.json` |
| Export CSV | `--export report.csv` | `--export report.csv` |
| Deactivate | `deactivate` | `deactivate` |

---

 ## 34\. One-Minute Quick Start

 ### Kali/Linux

```
cd Packet-Sniffer-Using-Python
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 sniffer.py --read-pcap capture.pcap
```

 ### Windows

```
cd Packet-Sniffer-Using-Python
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python sniffer.py --read-pcap capture.pcap
```

