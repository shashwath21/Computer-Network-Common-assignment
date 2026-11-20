"""
Network Security and Firewall Monitoring System
Student: Shashwath P
Register Number: 1924260377

This is an educational firewall-monitoring simulator. It evaluates
user-entered traffic records against configurable rules. It does not
capture live packets or change the host operating system's firewall.
"""

import csv
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime


class FirewallMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Security and Firewall Monitoring System")
        self.root.geometry("1120x720")
        self.root.minsize(950, 620)

        self.rules = [
            {"source": "192.168.1.10", "destination": "192.168.1.100",
             "port": 80, "protocol": "TCP", "action": "ALLOW"},
            {"source": "192.168.1.20", "destination": "192.168.1.100",
             "port": 443, "protocol": "TCP", "action": "ALLOW"},
            {"source": "192.168.1.30", "destination": "192.168.1.100",
             "port": 53, "protocol": "UDP", "action": "ALLOW"},
        ]
        self.events = []
        self.build_ui()
        self.refresh_rules()
        self.update_dashboard()

    def build_ui(self):
        title = ttk.Label(self.root, text="NETWORK SECURITY & FIREWALL MONITOR",
                          font=("Arial", 18, "bold"))
        title.pack(pady=(12, 8))

        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)

        traffic = ttk.LabelFrame(main, text="Traffic inspection", padding=10)
        traffic.pack(fill="x", pady=5)

        self.vars = {
            "source": tk.StringVar(value="192.168.1.10"),
            "destination": tk.StringVar(value="192.168.1.100"),
            "port": tk.StringVar(value="80"),
            "protocol": tk.StringVar(value="TCP"),
            "direction": tk.StringVar(value="Outgoing"),
        }
        fields = [
            ("Source IP", "source"), ("Destination IP", "destination"),
            ("Port", "port")
        ]
        for col, (label, key) in enumerate(fields):
            ttk.Label(traffic, text=label).grid(row=0, column=col, sticky="w", padx=5)
            ttk.Entry(traffic, textvariable=self.vars[key], width=23).grid(
                row=1, column=col, padx=5, pady=4, sticky="ew")
        ttk.Label(traffic, text="Protocol").grid(row=0, column=3, sticky="w", padx=5)
        ttk.Combobox(traffic, textvariable=self.vars["protocol"],
                     values=["TCP", "UDP"], state="readonly", width=12).grid(
                         row=1, column=3, padx=5, pady=4)
        ttk.Label(traffic, text="Direction").grid(row=0, column=4, sticky="w", padx=5)
        ttk.Combobox(traffic, textvariable=self.vars["direction"],
                     values=["Incoming", "Outgoing"], state="readonly", width=12).grid(
                         row=1, column=4, padx=5, pady=4)
        ttk.Button(traffic, text="Inspect traffic",
                   command=self.inspect_traffic).grid(row=1, column=5, padx=10)

        rules_frame = ttk.LabelFrame(main, text="Firewall rules (first matching rule wins)", padding=8)
        rules_frame.pack(fill="x", pady=5)
        self.rule_tree = ttk.Treeview(
            rules_frame, columns=("src", "dst", "port", "protocol", "action"),
            show="headings", height=4)
        for col, heading, width in [
            ("src", "Source IP", 190), ("dst", "Destination IP", 190),
            ("port", "Port", 80), ("protocol", "Protocol", 100),
            ("action", "Action", 100)
        ]:
            self.rule_tree.heading(col, text=heading)
            self.rule_tree.column(col, width=width, anchor="center")
        self.rule_tree.pack(fill="x")

        add = ttk.Frame(rules_frame)
        add.pack(fill="x", pady=(8, 0))
        self.new_rule = {
            "source": tk.StringVar(), "destination": tk.StringVar(),
            "port": tk.StringVar(value="80"), "protocol": tk.StringVar(value="TCP"),
            "action": tk.StringVar(value="ALLOW")
        }
        for label, key, width in [
            ("New source", "source", 18), ("New destination", "destination", 18),
            ("Port", "port", 7)
        ]:
            ttk.Label(add, text=label).pack(side="left", padx=(4, 2))
            ttk.Entry(add, textvariable=self.new_rule[key], width=width).pack(side="left", padx=2)
        ttk.Combobox(add, textvariable=self.new_rule["protocol"],
                     values=["TCP", "UDP"], state="readonly", width=7).pack(side="left", padx=3)
        ttk.Combobox(add, textvariable=self.new_rule["action"],
                     values=["ALLOW", "BLOCK"], state="readonly", width=8).pack(side="left", padx=3)
        ttk.Button(add, text="Add rule", command=self.add_rule).pack(side="left", padx=5)

        dash = ttk.LabelFrame(main, text="Network traffic dashboard", padding=8)
        dash.pack(fill="x", pady=5)
        self.total_var = tk.StringVar(value="Total: 0")
        self.allowed_var = tk.StringVar(value="Allowed: 0")
        self.blocked_var = tk.StringVar(value="Blocked: 0")
        for var in (self.total_var, self.allowed_var, self.blocked_var):
            ttk.Label(dash, textvariable=var, font=("Arial", 11, "bold")).pack(
                side="left", padx=25, pady=5)

        logs = ttk.LabelFrame(main, text="Traffic and security log", padding=8)
        logs.pack(fill="both", expand=True, pady=5)
        cols = ("time", "source", "destination", "port", "protocol",
                "direction", "status", "suspicious")
        self.log_tree = ttk.Treeview(logs, columns=cols, show="headings")
        headings = ["Time", "Source IP", "Destination IP", "Port", "Protocol",
                    "Direction", "Access status", "Suspicious"]
        widths = [145, 125, 135, 55, 75, 85, 100, 90]
        for col, heading, width in zip(cols, headings, widths):
            self.log_tree.heading(col, text=heading)
            self.log_tree.column(col, width=width, anchor="center")
        self.log_tree.pack(fill="both", expand=True)
        bottom = ttk.Frame(main)
        bottom.pack(fill="x", pady=5)
        ttk.Button(bottom, text="Export log as CSV", command=self.export_csv).pack(side="left")
        ttk.Button(bottom, text="Load demonstration traffic",
                   command=self.demo_traffic).pack(side="left", padx=8)
        ttk.Button(bottom, text="Clear displayed events",
                   command=self.clear_events).pack(side="left")

    @staticmethod
    def valid_ip(value):
        try:
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False

    def add_rule(self):
        r = self.new_rule
        source, destination = r["source"].get().strip(), r["destination"].get().strip()
        try:
            port = int(r["port"].get())
            if not (self.valid_ip(source) and self.valid_ip(destination)):
                raise ValueError("Enter valid source and destination IP addresses.")
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
        except ValueError as exc:
            messagebox.showerror("Invalid firewall rule", str(exc))
            return
        self.rules.append({
            "source": source, "destination": destination, "port": port,
            "protocol": r["protocol"].get(), "action": r["action"].get()
        })
        self.refresh_rules()

    def refresh_rules(self):
        for item in self.rule_tree.get_children():
            self.rule_tree.delete(item)
        for rule in self.rules:
            self.rule_tree.insert("", "end", values=(
                rule["source"], rule["destination"], rule["port"],
                rule["protocol"], rule["action"]))

    def evaluate(self, source, destination, port, protocol):
        for rule in self.rules:
            if (rule["source"] == source and rule["destination"] == destination
                    and rule["port"] == port and rule["protocol"] == protocol):
                return rule["action"]
        return "BLOCK"  # Default-deny policy

    def inspect_traffic(self):
        source = self.vars["source"].get().strip()
        destination = self.vars["destination"].get().strip()
        protocol = self.vars["protocol"].get()
        direction = self.vars["direction"].get()
        try:
            port = int(self.vars["port"].get())
            if not self.valid_ip(source) or not self.valid_ip(destination):
                raise ValueError("Source and destination must be valid IP addresses.")
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
        except ValueError as exc:
            messagebox.showerror("Invalid traffic details", str(exc))
            return

        action = self.evaluate(source, destination, port, protocol)
        status = "Allowed" if action == "ALLOW" else "Blocked"
        suspicious = "Yes" if action == "BLOCK" else "No"
        alert = "Unauthorized access attempt" if action == "BLOCK" else "None"
        event = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": source, "destination": destination, "port": port,
            "protocol": protocol, "direction": direction, "status": status,
            "suspicious": suspicious, "alert": alert
        }
        self.events.append(event)
        self.log_tree.insert("", "end", values=(
            event["time"], source, destination, port, protocol,
            direction, status, suspicious))
        self.append_text_log(event)
        self.update_dashboard()
        if action == "BLOCK":
            messagebox.showwarning("Security alert", alert + " detected from " + source)

    @staticmethod
    def append_text_log(event):
        with open("security_log.txt", "a", encoding="utf-8") as f:
            f.write(
                f'{event["time"]}, {event["source"]}, {event["destination"]}, '
                f'{event["port"]}, {event["protocol"]}, {event["direction"]}, '
                f'{event["status"]}, suspicious={event["suspicious"]}, '
                f'alert={event["alert"]}\n'
            )

    def update_dashboard(self):
        allowed = sum(e["status"] == "Allowed" for e in self.events)
        blocked = sum(e["status"] == "Blocked" for e in self.events)
        self.total_var.set(f"Total: {len(self.events)}")
        self.allowed_var.set(f"Allowed: {allowed}")
        self.blocked_var.set(f"Blocked: {blocked}")

    def demo_traffic(self):
        samples = [
            ("192.168.1.10", "192.168.1.100", "80", "TCP", "Outgoing"),
            ("192.168.1.20", "192.168.1.100", "443", "TCP", "Outgoing"),
            ("192.168.1.50", "192.168.1.100", "22", "TCP", "Incoming"),
            ("192.168.1.30", "192.168.1.100", "53", "UDP", "Incoming"),
            ("192.168.1.99", "192.168.1.100", "23", "TCP", "Incoming"),
        ]
        for source, destination, port, protocol, direction in samples:
            self.vars["source"].set(source)
            self.vars["destination"].set(destination)
            self.vars["port"].set(port)
            self.vars["protocol"].set(protocol)
            self.vars["direction"].set(direction)
            self.inspect_traffic()

    def export_csv(self):
        if not self.events:
            messagebox.showinfo("Export", "There are no events to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
            initialfile="network_security_log.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.events[0].keys())
            writer.writeheader()
            writer.writerows(self.events)
        messagebox.showinfo("Export", "Security log exported successfully.")

    def clear_events(self):
        self.events.clear()
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        self.update_dashboard()


if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallMonitor(root)
    root.mainloop()
