import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP, conf

# GUI Application Class
class NetworkReconApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Recon Tool")
        self.root.geometry("600x500")

        # Target IP Input
        tk.Label(root, text="Target IP:").pack()
        self.target_ip_entry = tk.Entry(root, width=30)
        self.target_ip_entry.pack()

        # Port Range Inputs
        tk.Label(root, text="Start Port:").pack()
        self.start_port_entry = tk.Entry(root, width=10)
        self.start_port_entry.pack()

        tk.Label(root, text="End Port:").pack()
        self.end_port_entry = tk.Entry(root, width=10)
        self.end_port_entry.pack()

        # Buttons for Scanning & Sniffing
        self.scan_button = tk.Button(root, text="Start Port Scan", command=self.start_scan)
        self.scan_button.pack(pady=5)

        self.sniff_button = tk.Button(root, text="Start Packet Sniffer", command=self.start_sniffing)
        self.sniff_button.pack(pady=5)

        self.stop_sniff_button = tk.Button(root, text="Stop Packet Sniffer", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_sniff_button.pack(pady=5)

        # Output Box
        self.output_box = scrolledtext.ScrolledText(root, width=70, height=15)
        self.output_box.pack(pady=10)

        # Threads & Flags
        self.scan_thread = None
        self.sniff_thread = None
        self.sniffing = False  # Flag to control sniffing

    def update_output(self, message):
        """ Safely update the GUI from another thread """
        self.output_box.insert(tk.END, message + "\n")
        self.output_box.see(tk.END)

    # Port Scanner Function
    def port_scanner(self, target_host, start_port, end_port):
        self.output_box.after(0, self.update_output, f"Scanning {target_host}...\n")
        for port in range(start_port, end_port + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target_host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown Service"
                self.output_box.after(0, self.update_output, f"[+] Open Port: {port} ({service})")
            s.close()
        self.output_box.after(0, self.update_output, "Port Scanning Completed.")

    # Packet Sniffer Function
    def packet_sniffer(self):
        self.output_box.after(0, self.update_output, "[!] Starting Packet Sniffer...")
        self.sniffing = True
        self.stop_sniff_button.config(state=tk.NORMAL)  # Enable Stop button

        def process_packet(packet):
            if not self.sniffing:
                return False  # Stop sniffing gracefully
            if IP in packet:
                protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
                message = f"[Packet] {packet[IP].src} → {packet[IP].dst} | Protocol: {protocol}"
                self.output_box.after(0, self.update_output, message)

        # Automatically detect network interface
        interface = conf.iface
        self.output_box.after(0, self.update_output, f"Using network interface: {interface}")

        # Start sniffing (needs root/admin privileges)
        try:
            sniff(prn=process_packet, iface=interface, store=False, stop_filter=lambda p: not self.sniffing)
        except PermissionError:
            self.output_box.after(0, self.update_output, "[Error] Run this script as Administrator or use sudo.")

        self.output_box.after(0, self.update_output, "[!] Packet Sniffer Stopped.")
        self.stop_sniff_button.config(state=tk.DISABLED)  # Disable Stop button

    # Start Port Scan Thread
    def start_scan(self):
        target_ip = self.target_ip_entry.get()
        try:
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            if start_port > end_port:
                messagebox.showerror("Error", "Start port must be lower than end port.")
                return
            self.scan_thread = threading.Thread(target=self.port_scanner, args=(target_ip, start_port, end_port))
            self.scan_thread.start()
        except ValueError:
            messagebox.showerror("Error", "Invalid port numbers.")

    # Start Packet Sniffer Thread
    def start_sniffing(self):
        if not self.sniffing:
            self.sniff_thread = threading.Thread(target=self.packet_sniffer, daemon=True)
            self.sniff_thread.start()

    # Stop Packet Sniffing
    def stop_sniffing(self):
        self.sniffing = False
        self.output_box.after(0, self.update_output, "[!] Stopping Packet Sniffer...")

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkReconApp(root)
    root.mainloop()
