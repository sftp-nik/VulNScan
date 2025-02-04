import tkinter as tk
from tkinter import messagebox, ttk
import nmap
import xlsxwriter
import os
import requests
import re
import threading
import smtplib
from email.mime.text import MIMEText
import logging
import matplotlib.pyplot as plt

logging.basicConfig(filename='vulnerability_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')   #logging setup

class VulnerabilityScanner:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Vulnerability Scanner")
        self.window.geometry("600x600")
        self.window.configure(bg="#f0f0f0")

        #main
        self.main_frame = tk.Frame(self.window, bg="#f0f0f0", padx=10, pady=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # gen title
        self.title_label = tk.Label(self.main_frame, text="Vulnerability Scanner", font=("Arial", 16, "bold"), bg="#f0f0f0")
        self.title_label.pack(pady=(0, 10))

        # IP input
        self.ip_label = tk.Label(self.main_frame, text="Enter IP Addresses (comma separated):", bg="#f0f0f0")
        self.ip_label.pack()
        self.ip_entry = tk.Entry(self.main_frame, width=50)
        self.ip_entry.pack(pady=(0, 10))

        # scan output
        self.scan_options_label = tk.Label(self.main_frame, text="Nmap Scan Options:", bg="#f0f0f0")
        self.scan_options_label.pack()
        self.scan_options_entry = tk.Entry(self.main_frame, width=50)
        self.scan_options_entry.pack(pady=(0, 10))
        self.scan_options_entry.insert(0, "-T4 -p- --script vuln")  # Default 

        # email notf.
        self.email_label = tk.Label(self.main_frame, text="Email for notifications (optional):", bg="#f0f0f0")
        self.email_label.pack()
        self.email_entry = tk.Entry(self.main_frame, width=50)
        self.email_entry.pack(pady=(0, 10))

        # scan  btn
        self.scan_button = tk.Button(self.main_frame, text="Scan", command=self.scan, bg="#007acc", fg="white", font=("Arial", 12))
        self.scan_button.pack(pady=(10, 20))

        # output box
        self.output_frame = tk.Frame(self.main_frame, bg="#f0f0f0")
        self.output_frame.pack()

        self.output_text = tk.Text(self.output_frame, width=70, height=15, wrap=tk.WORD)
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar = tk.Scrollbar(self.output_frame, command=self.output_text.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.output_text.config(yscrollcommand=self.scrollbar.set)

        # progress bar
        self.progress = ttk.Progressbar(self.main_frame, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=(10, 10))

        # status bar
        self.status_label = tk.Label(self.main_frame, text="Status: Idle", bg="#f0f0f0", font=("Arial", 10))
        self.status_label.pack(pady=(10, 0))

    def is_valid_ip(self, ip):
        """Check if the given string is a valid IP address."""
        pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        return pattern.match(ip) is not None

    def send_email_notification(self, subject, body):
        """Send an email notification after the scan."""
        email = self.email_entry.get()
        if email:
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = 'kulkarninikhil575@gmail.com'  # your mail 
            msg['To'] = email

            try:
                with smtplib.SMTP('smtp.example.com', 587) as server:  # smtp server
                    server.starttls()
                    server.login('kulkarninikhil575@gmail.com', 'password')  # email creds
                    server.send_message(msg)
            except Exception as e:
                logging.error(f"Failed to send email: {e}")
                messagebox.showerror("Error", "Failed to send email notification.")

    def get_vulnerability_info(self, vuln):
        """Fetch CVE details from NVD API."""
        nvd_api_url = f'https://services.nvd.nist.gov/rest/json/cve/1.0/{vuln}'
        response = requests.get(nvd_api_url)

        if response.status_code == 200:
            data = response.json()
            if 'result' in data and data['result']['CVE_Items']:
                cve_item = data['result']['CVE_Items'][0]
                cve_id = cve_item['cve']['CVE_data_meta']['ID']
                description = cve_item['cve']['description']['description_data'][0]['value']
                cvss = cve_item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 'N/A')
                return cve_id, description, cvss
        return None, None, None

    def find_solution(self, vuln):
        """Query NVD API to find potential solutions."""
        nvd_api_url = f'https://services.nvd.nist.gov/rest/json/cve/1.0/{vuln}'
        response = requests.get(nvd_api_url)

        if response.status_code == 200:
            data = response.json()
            if 'result' in data and data['result']['CVE_Items']:
                cve_item = data['result']['CVE_Items'][0]
                references = cve_item['cve']['references']['reference_data']
                remediation_links = [ref['url'] for ref in references if 'solution' in ref.get('tags', [])]
                return remediation_links
        return None

    def run_scan_thread(self, ip_address, scan_options):
        """Run the scan for a single IP address in a separate thread."""
        ip_address = ip_address.strip()
        print(f"Scanning {ip_address}...")
        self.output_text.insert(tk.END, f"Scanning {ip_address}...\n")

        # to run nmap scan to find open ports
        nm = nmap.PortScanner()
        nm.scan(ip_address, arguments=scan_options)
        open_ports = [port for port in nm[ip_address].all_tcp() if nm[ip_address].tcp(port)['state'] == 'open']

        # to run nmap vulnerability scan
        nm_vuln = nmap.PortScanner()
        nm_vuln.scan(ip_address, arguments=scan_options)
        vuln_results = nm_vuln[ip_address].get('scan', {}).get('tcp', {})

        # Process vulnerability results
        for port, vuln_data in vuln_results.items():
            if 'script' in vuln_data and 'vuln' in vuln_data['script']:
                vuln = vuln_data['script']['vuln']
                cve_id, description, cvss = self.get_vulnerability_info(vuln)
                remediation_links = self.find_solution(vuln)

                if cve_id and description and cvss:
                    print(f"Vulnerability found: {cve_id} - {description} (CVSS: {cvss})")
                    self.output_text.insert(tk.END, f"Vulnerability found: {cve_id} - {description} (CVSS: {cvss})\n")

                    if remediation_links:
                        print(f"Remediation links: {', '.join(remediation_links)}")
                        self.output_text.insert(tk.END, f"Remediation links: {', '.join(remediation_links)}\n")

    def scan(self):
        """Run the vulnerability scan and fetch CVE info and solutions."""
        ip_addresses = self.ip_entry.get().split(',')
        scan_options = self.scan_options_entry.get()

        # IP addd. validation alg.
        for ip in ip_addresses:
            if not self.is_valid_ip(ip.strip()):
                messagebox.showerror("Error", f"Invalid IP address: {ip.strip()}")
                return

        # will clear output box
        self.output_text.delete(1.0, tk.END)

        # will create threads for scanning
        threads = []
        for ip_address in ip_addresses:
            thread = threading.Thread(target=self.run_scan_thread, args=(ip_address, scan_options))
            threads.append(thread)
            thread.start()

        # to update progress bar
        for row in range(len(ip_addresses)):
            self.progress['value'] = (row / len (ip_addresses)) * 100
            self.window.update_idletasks()

        # will wait for all threds to finish
        for thread in threads:
            thread.join()

        # Send email notf. (Optional)
        self.send_email_notification("Vulnerability Scan Results", self.output_text.get(1.0, tk.END))

        # Export results into an excel file
        workbook = xlsxwriter.Workbook('vulnerability_scan_results.xlsx')
        worksheet = workbook.add_worksheet()
        worksheet.write(0, 0, "IP Address")
        worksheet.write(0, 1, "Vulnerability")
        worksheet.write(0, 2, "Description")
        worksheet.write(0, 3, "CVSS")
        worksheet.write(0, 4, "Remediation Links")

        row = 1
        for line in self.output_text.get(1.0, tk.END).split('\n'):
            if line:
                parts = line.split(' - ')
                if len(parts) > 1:
                    worksheet.write(row, 0, parts[0])
                    worksheet.write(row, 1, parts[1].split(' (')[0])
                    worksheet.write(row, 2, parts[1].split(' (')[1].split(')')[0])
                    worksheet.write(row, 3, parts[1].split(' (')[1].split(')')[1].split(' ')[1])
                    worksheet.write(row, 4, ', '.join(self.find_solution(parts[1].split(' - ')[1].split(' (')[0])))
                    row += 1

        workbook.close()

        # Graphical visualization with the use of matplotlib
        cvss_scores = []
        for line in self.output_text.get(1.0, tk.END).split('\n'):
            if line:
                parts = line.split(' - ')
                if len(parts) > 1:
                    cvss_scores.append(float(parts[1].split(' (')[1].split(')')[1].split(' ')[1]))

        plt.hist(cvss_scores, bins=10)
        plt.xlabel('CVSS Score ')
        plt.ylabel('Frequency')
        plt.title('CVSS Score Distribution')
        plt.show()

    def run(self):
        self.window.mainloop()

'''if __name__ == "__main__":
 #   scanner = VulnerabilityScanner()
  #  scanner.run()'''

if __name__ == "__main__":
    scanner = VulnerabilityScanner()
    scanner.run()


# Nik
