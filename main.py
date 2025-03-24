import nmap
import requests
import threading
import smtplib
import logging
import openpyxl
import time
from tkinter import *
from tkinter import ttk
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class VulnerabilityScanner:
    def __init__(self, master):
        self.master = master
        self.master.title("Nmap Vulnerability Scanner")
        self.master.geometry("500x450")
        
        Label(master, text="Enter Target IP:").pack()
        self.target_entry = Entry(master)
        self.target_entry.pack()
        
        self.scan_button = Button(master, text="Scan", command=self.start_scan)
        self.scan_button.pack()
        
        self.skip_email_var = IntVar()
        self.skip_email_check = Checkbutton(master, text="Skip Email Report", variable=self.skip_email_var)
        self.skip_email_check.pack()
        
        self.progress = ttk.Progressbar(master, orient=HORIZONTAL, length=300, mode='determinate')
        self.progress.pack()
        
        self.result_text = Text(master, height=10, width=60)
        self.result_text.pack()
    
    def start_scan(self):
        target = self.target_entry.get()
        if not target:
            logging.error("Target IP is required!")
            return
        
        self.progress["value"] = 0
        threading.Thread(target=self.scan_target, args=(target,), daemon=True).start()
    
    def scan_target(self, target):
        logging.info(f"Starting scan on {target}")
        nm = nmap.PortScanner()
        self.progress["value"] = 20
        self.master.update_idletasks()
        
        nm.scan(target, arguments="-sV --script=vuln")
        self.progress["value"] = 50  # Update progress
        self.master.update_idletasks()
        
        result = self.parse_nmap_results(nm, target)
        
        self.progress["value"] = 75  # Update progress
        self.master.update_idletasks()
        
        self.result_text.insert(END, result + "\n")
        self.export_to_excel(target, result)
        
        if not self.skip_email_var.get():
            self.send_email_report(target, result)
        
        self.progress["value"] = 100  # Final progress
        self.master.update_idletasks()
    
    def parse_nmap_results(self, nm, target):
        logging.info(f"Parsing scan results for {target}")
        try:
            report = ""
            for host in nm.all_hosts():
                for port in nm[host]['tcp']:
                    state = nm[host]['tcp'][port]['state']
                    service = nm[host]['tcp'][port]['name']
                    report += f"Port: {port}, State: {state}, Service: {service}\n"
                    
                    # Extract vulnerabilities if available
                    if 'script' in nm[host]['tcp'][port]:
                        for script, output in nm[host]['tcp'][port]['script'].items():
                            report += f"  - {script}: {output}\n"
            return report
        except Exception as e:
            logging.error(f"Error parsing results: {e}")
            return "Error in parsing scan results"
    
    def export_to_excel(self, target, result):
        logging.info(f"Exporting scan results for {target} to Excel")
        try:
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.append(["Port", "State", "Service", "Vulnerability Info"])
            
            for line in result.strip().split("\n"):
                if line.startswith("Port"):
                    parts = line.split(", ")
                    port = parts[0].split(": ")[1]
                    state = parts[1].split(": ")[1]
                    service = parts[2].split(": ")[1]
                    vuln_info = "; ".join([l.strip() for l in result.strip().split("\n") if "- " in l])
                    ws.append([port, state, service, vuln_info])
            
            file_name = f"scan_results_{target}.xlsx"
            wb.save(file_name)
            logging.info(f"Results saved to {file_name}")
        except Exception as e:
            logging.error(f"Error exporting to Excel: {e}")
    
    def send_email_report(self, target, result):
        logging.info(f"Sending email report for {target}")
        try:
            sender_email = "your_email@example.com"
            receiver_email = "recipient@example.com"
            password = "your_password"
            
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = receiver_email
            msg['Subject'] = f"Scan Report for {target}"
            msg.attach(MIMEText(result, 'plain'))
            
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, password)
            server.send_message(msg)
            server.quit()
            logging.info("Email sent successfully")
        except Exception as e:
            logging.error(f"Failed to send email: {e}")

if __name__ == "__main__":
    root = Tk()
    app = VulnerabilityScanner(root)
    root.mainloop()
