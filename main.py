import tkinter as tk
from tkinter import messagebox
import nmap
import subprocess
import xlsxwriter
import os

class VulnerabilityScanner:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Vulnerability Scanner")

        # Create input box for IP addresses
        self.ip_label = tk.Label(self.window, text="Enter IP Addresses (comma separated):")
        self.ip_label.pack()
        self.ip_entry = tk.Entry(self.window, width=40)
        self.ip_entry.pack()

        # Create buttons
        self.scan_button = tk.Button(self.window, text="Scan", command=self.scan)
        self.scan_button.pack()

        # Create text box for output
        self.output_text = tk.Text(self.window, width=60, height=20)
        self.output_text.pack()

    def scan(self):
        ip_addresses = self.ip_entry.get().split(',')
        if not ip_addresses:
            messagebox.showerror("Error", "Please enter IP addresses")
            return

        self.output_text.delete(1.0, tk.END)

        # Create Excel file
        workbook = xlsxwriter.Workbook('vulnerability_scan.xlsx')
        worksheet = workbook.add_worksheet()

        # Set header row
        worksheet.write(0, 0, 'IP Address')
        worksheet.write(0, 1, 'Open Ports')
        worksheet.write(0, 2, 'Vulnerabilities')

        row = 1
        for ip_address in ip_addresses:
            ip_address = ip_address.strip()
            print(f"Scanning {ip_address}...")

            # Run nmap scan to find open ports
            nm = nmap.PortScanner()
            nm.scan(ip_address, arguments="-T4 -p-")

            # Get open ports
            open_ports = [port for port in nm[ip_address].all_tcp() if nm[ip_address].tcp(port)['state'] == 'open']

            # Run nmap vulnerability scan
            nm_vuln = nmap.PortScanner()
            nm_vuln.scan(ip_address, arguments="-T4 -p- --script vuln")

            # Get vulnerabilities
            vulns = []
            for port in nm_vuln[ip_address].all_tcp():
                if 'script' in nm_vuln[ip_address].tcp(port):
                    vulns.extend(nm_vuln[ip_address].tcp(port)['script'].keys())

            # Write to Excel file
            worksheet.write(row, 0, ip_address)
            worksheet.write(row, 1, ', '.join(map(str, open_ports)))
            worksheet.write(row, 2, ', '.join(vulns))

            # Write to Tkinter window
            self.output_text.insert(tk.END, f"IP Address: {ip_address}\n")
            self.output_text.insert(tk.END, f"Open Ports: {', '.join(map(str, open_ports))}\n")
            self.output_text.insert(tk.END, f"Vulnerabilities: {', '.join(vulns)}\n\n")

            row += 1

        # Save the workbook to the current working directory
        workbook.close()

        # Show a message box with the path where the file was saved
        messagebox.showinfo("Scan Complete", f"Scan complete. Results saved to {os.getcwd()}/vulnerability_scan.xlsx")

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    scanner = VulnerabilityScanner()
    scanner.run()
