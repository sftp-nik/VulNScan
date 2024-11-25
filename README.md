# VulNScan

Note: This only works in a Linux machine with Metasploitable Framework

## Features
- Scan multiple IP addresses for open ports and vulnerabilities.
- Display results within the application window.
- Save scan results to an Excel file (`vulnerability_scan.xlsx`) in the current working directory.

## Requirements
- Python 3.x
- `tkinter` for the GUI interface
- `nmap` for scanning (install `python-nmap`)
- `xlsxwriter` for creating Excel files

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/sftp-nik/VulNScan/
   cd VulNScan
   ```

2. Install the required Python packages:
   ```bash
   pip install python-nmap xlsxwriter
   ```

3. Install `nmap` (if not already installed). Instructions vary by OS:
   - **Linux**: `sudo apt-get install nmap`
   - **macOS**: `brew install nmap`
   - **Windows**: Download and install from the [nmap website](https://nmap.org/download.html).

## Usage

1. Run the script:
   ```bash
   main.py
   ```

2. Enter the IP addresses to scan, separated by commas (e.g., `192.168.1.1, 192.168.1.2`).
3. Click the **Scan** button to initiate the scan.

After the scan completes, the results will be displayed within the application window, and an Excel file (`vulnerability_scan.xlsx`) will be created in the current directory.

## Notes

- Make sure you have the necessary permissions to run `nmap` on the network.
- Scanning a network without authorization is illegal.
- 
