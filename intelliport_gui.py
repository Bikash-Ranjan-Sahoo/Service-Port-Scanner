
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import csv
import os
import datetime


from scanner      import scan_target, validate_ip
from ai_predictor import AIPredictor


BG_DARK     = "#0d1117"   # Main background (very dark)
BG_CARD     = "#161b22"   # Card/panel background
BG_INPUT    = "#21262d"   # Input field background
ACCENT      = "#00b4d8"   # Cyan accent (titles, highlights)
ACCENT2     = "#7c3aed"   # Purple accent
TEXT_WHITE  = "#e6edf3"   # Main text color
TEXT_GREY   = "#8b949e"   # Secondary text
GREEN       = "#00c853"   # Safe
YELLOW      = "#ffd600"   # Suspicious
RED         = "#d50000"   # Dangerous
ORANGE      = "#ff6d00"   # High risk


DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139,
    143, 443, 445, 512, 513, 514, 1080, 1433,
    1521, 2049, 3306, 3389, 4444, 5432, 5900,
    5985, 6379, 8080, 8443, 8888, 9200, 27017
]



class IntelliPortApp:

    def __init__(self, root):
        """Set up the main application window."""
        self.root       = root
        self.predictor  = AIPredictor()   
        self.scan_results = []            
        self.stop_flag    = [False]       
        self.is_scanning  = False         

    
        self.root.title("IntelliPort — AI Powered Port Scanner")
        self.root.geometry("1000x750")
        self.root.configure(bg=BG_DARK)
        self.root.resizable(True, True)

      
        self._build_header()
        self._build_input_section()
        self._build_controls()
        self._build_quick_checker()   
        self._build_results_table()
        self._build_threat_score()
        self._build_status_bar()

   
    def _build_header(self):
        """Create the top header with logo and title."""
        header = tk.Frame(self.root, bg=BG_DARK, pady=10)
        header.pack(fill="x", padx=20)

       
        tk.Label(
            header,
            text="🔍 IntelliPort",
            font=("Courier New", 26, "bold"),
            bg=BG_DARK,
            fg=ACCENT
        ).pack(side="left")

   
        tk.Label(
            header,
            text="  AI Powered Network Port Scanner",
            font=("Courier New", 12),
            bg=BG_DARK,
            fg=TEXT_GREY
        ).pack(side="left", pady=5)

     
        tk.Frame(self.root, bg=ACCENT, height=1).pack(fill="x", padx=20)

   
    def _build_input_section(self):
        """Create the IP input and port configuration panel."""
        frame = tk.Frame(self.root, bg=BG_CARD, padx=15, pady=12)
        frame.pack(fill="x", padx=20, pady=(10, 5))

   
        row1 = tk.Frame(frame, bg=BG_CARD)
        row1.pack(fill="x")

        tk.Label(row1, text="Target IP:", font=("Courier New", 11, "bold"),
                 bg=BG_CARD, fg=ACCENT, width=12, anchor="w").pack(side="left")

        self.ip_var = tk.StringVar(value="127.0.0.1")
        ip_entry = tk.Entry(row1, textvariable=self.ip_var,
                            font=("Courier New", 12), bg=BG_INPUT,
                            fg=TEXT_WHITE, insertbackground=ACCENT,
                            relief="flat", width=20)
        ip_entry.pack(side="left", padx=(5, 20), ipady=4)

      
        def _sync_ip(*args):
            if hasattr(self, "qc_ip_var"):
                self.qc_ip_var.set(self.ip_var.get())
        self.ip_var.trace_add("write", _sync_ip)

        tk.Label(row1, text="Quick:", font=("Courier New", 10),
                 bg=BG_CARD, fg=TEXT_GREY).pack(side="left")

        for label, ip in [("Localhost", "127.0.0.1"), ("Gateway", "192.168.1.1")]:
            tk.Button(
                row1, text=label,
                command=lambda i=ip: self.ip_var.set(i),
                font=("Courier New", 9), bg=BG_INPUT,
                fg=ACCENT, relief="flat", cursor="hand2",
                padx=8
            ).pack(side="left", padx=3)

        row2 = tk.Frame(frame, bg=BG_CARD)
        row2.pack(fill="x", pady=(8, 0))

        tk.Label(row2, text="Ports:", font=("Courier New", 11, "bold"),
                 bg=BG_CARD, fg=ACCENT, width=12, anchor="w").pack(side="left")

        self.port_mode = tk.StringVar(value="common")
        modes = [("Common Ports", "common"), ("Top 1000", "top1000"),
                 ("Custom Range", "custom")]
        for text, val in modes:
            tk.Radiobutton(
                row2, text=text, variable=self.port_mode,
                value=val, bg=BG_CARD, fg=TEXT_WHITE,
                selectcolor=BG_INPUT, font=("Courier New", 10),
                activebackground=BG_CARD
            ).pack(side="left", padx=5)

        tk.Label(row2, text="  Custom:", font=("Courier New", 10),
                 bg=BG_CARD, fg=TEXT_GREY).pack(side="left")

        self.custom_ports_var = tk.StringVar(value="80,443,22,21")
        tk.Entry(row2, textvariable=self.custom_ports_var,
                 font=("Courier New", 10), bg=BG_INPUT,
                 fg=TEXT_WHITE, insertbackground=ACCENT,
                 relief="flat", width=25).pack(side="left", padx=5, ipady=3)

    
    def _build_controls(self):
        """Create Scan, Stop, Export buttons."""
        frame = tk.Frame(self.root, bg=BG_DARK, pady=5)
        frame.pack(fill="x", padx=20)

     
        self.scan_btn = tk.Button(
            frame, text="▶  START SCAN",
            command=self._start_scan,
            font=("Courier New", 12, "bold"),
            bg=ACCENT, fg=BG_DARK,
            relief="flat", cursor="hand2",
            padx=20, pady=6
        )
        self.scan_btn.pack(side="left", padx=(0, 10))

        # STOP button
        self.stop_btn = tk.Button(
            frame, text="⏹  STOP",
            command=self._stop_scan,
            font=("Courier New", 12, "bold"),
            bg=TEXT_GREY, fg=BG_DARK,
            relief="flat", cursor="hand2",
            padx=20, pady=6, state="disabled"
        )
        self.stop_btn.pack(side="left", padx=(0, 10))

        # EXPORT button
        tk.Button(
            frame, text="💾  EXPORT CSV",
            command=self._export_results,
            font=("Courier New", 12, "bold"),
            bg=ACCENT2, fg=TEXT_WHITE,
            relief="flat", cursor="hand2",
            padx=20, pady=6
        ).pack(side="left", padx=(0, 10))

        # CLEAR button
        tk.Button(
            frame, text="🗑  CLEAR",
            command=self._clear_results,
            font=("Courier New", 12),
            bg=BG_INPUT, fg=TEXT_WHITE,
            relief="flat", cursor="hand2",
            padx=15, pady=6
        ).pack(side="left")

        # Progress bar
        self.progress = ttk.Progressbar(
            frame, mode="indeterminate", length=180
        )
        self.progress.pack(side="right")

    # ----------------------------------------------------------
    # UI BUILDER: Quick Port Checker (NEW FEATURE)
    # ----------------------------------------------------------
    def _build_quick_checker(self):
        """
        Quick Port Checker panel.
        Lets the user instantly check if ONE specific port is open or not,
        without running a full scan.
        """
        # Outer frame with a distinct border color to separate it visually
        outer = tk.Frame(self.root, bg=ACCENT2, pady=1)
        outer.pack(fill="x", padx=20, pady=(4, 0))

        frame = tk.Frame(outer, bg=BG_CARD, padx=15, pady=8)
        frame.pack(fill="x")

        # Section title
        tk.Label(
            frame, text="⚡ Quick Port Checker",
            font=("Courier New", 11, "bold"),
            bg=BG_CARD, fg=ACCENT2
        ).pack(side="left", padx=(0, 15))

        # IP field (pre-filled from main IP input, but editable)
        tk.Label(frame, text="IP:", font=("Courier New", 10),
                 bg=BG_CARD, fg=TEXT_GREY).pack(side="left")

        self.qc_ip_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(
            frame, textvariable=self.qc_ip_var,
            font=("Courier New", 10), bg=BG_INPUT,
            fg=TEXT_WHITE, insertbackground=ACCENT,
            relief="flat", width=15
        ).pack(side="left", padx=(4, 12), ipady=3)

        # Port number field
        tk.Label(frame, text="Port:", font=("Courier New", 10),
                 bg=BG_CARD, fg=TEXT_GREY).pack(side="left")

        self.qc_port_var = tk.StringVar(value="80")
        tk.Entry(
            frame, textvariable=self.qc_port_var,
            font=("Courier New", 10), bg=BG_INPUT,
            fg=TEXT_WHITE, insertbackground=ACCENT,
            relief="flat", width=8
        ).pack(side="left", padx=(4, 12), ipady=3)

        # Quick-select common ports
        tk.Label(frame, text="Try:", font=("Courier New", 9),
                 bg=BG_CARD, fg=TEXT_GREY).pack(side="left")

        for p in [21, 22, 80, 443, 3306, 3389, 8080]:
            tk.Button(
                frame, text=str(p),
                command=lambda port=p: self.qc_port_var.set(str(port)),
                font=("Courier New", 9), bg=BG_INPUT,
                fg=ACCENT, relief="flat", cursor="hand2",
                padx=6, pady=1
            ).pack(side="left", padx=2)

        # CHECK button
        tk.Button(
            frame, text="🔎 CHECK",
            command=self._check_single_port,
            font=("Courier New", 10, "bold"),
            bg=ACCENT2, fg=TEXT_WHITE,
            relief="flat", cursor="hand2",
            padx=12, pady=3
        ).pack(side="left", padx=(12, 10))

        # Result label — shows the answer right here inline
        self.qc_result_var = tk.StringVar(value="← Enter an IP and port, then click CHECK")
        self.qc_result_label = tk.Label(
            frame,
            textvariable=self.qc_result_var,
            font=("Courier New", 10, "bold"),
            bg=BG_CARD, fg=TEXT_GREY
        )
        self.qc_result_label.pack(side="left", padx=8)

    # ----------------------------------------------------------
    # ACTION: Check Single Port (Quick Checker)
    # ----------------------------------------------------------
    def _check_single_port(self):
        """
        Instantly check if a single port is open, closed, or filtered.
        Runs in a background thread so the GUI doesn't freeze.
        """
        from scanner import scan_port, get_service, validate_ip as _validate

        ip   = self.qc_ip_var.get().strip()
        port_str = self.qc_port_var.get().strip()

        # --- Validate IP ---
        if not _validate(ip):
            self.qc_result_var.set("❌ Invalid IP address!")
            self.qc_result_label.config(fg=RED)
            return

        # --- Validate Port ---
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            self.qc_result_var.set("❌ Port must be a number between 1–65535")
            self.qc_result_label.config(fg=RED)
            return

        # Show "checking..." while we wait
        self.qc_result_var.set(f"⏳ Checking {ip}:{port} ...")
        self.qc_result_label.config(fg=YELLOW)

        def _do_check():
            """Runs in background thread."""
            status  = scan_port(ip, port, timeout=1.5)
            service = get_service(port)

            # Get AI risk prediction for this port
            ai_info = self.predictor.predict(port, "TCP", status)

            # Build display text based on status
            if status == "open":
                text  = f"🔓 Port {port} ({service}) is OPEN   {ai_info['emoji']} {ai_info['label']}"
                color = GREEN if ai_info["risk_level"] == 0 else (
                        YELLOW if ai_info["risk_level"] == 1 else RED)
            elif status == "filtered":
                text  = f"🛡  Port {port} ({service}) is FILTERED (firewall blocking)"
                color = YELLOW
            else:
                text  = f"🔒 Port {port} ({service}) is CLOSED"
                color = TEXT_GREY

            # Update GUI safely from background thread
            self.root.after(0, lambda: self.qc_result_var.set(text))
            self.root.after(0, lambda: self.qc_result_label.config(fg=color))
            self.root.after(0, lambda: self.status_var.set(
                f"Quick Check → {ip}:{port} — {status.upper()}  |  "
                f"AI Risk: {ai_info['label']}  |  {ai_info['recommendation']}"
            ))

        # Run in background so GUI stays responsive
        threading.Thread(target=_do_check, daemon=True).start()

    # ----------------------------------------------------------
    # UI BUILDER: Results Table
    # ----------------------------------------------------------
    def _build_results_table(self):
        """Build the main results Treeview table."""
        frame = tk.Frame(self.root, bg=BG_DARK)
        frame.pack(fill="both", expand=True, padx=20, pady=(5, 0))

        tk.Label(frame, text="📋 Scan Results",
                 font=("Courier New", 12, "bold"),
                 bg=BG_DARK, fg=ACCENT).pack(anchor="w")

        # Style the table
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                         background=BG_CARD,
                         foreground=TEXT_WHITE,
                         fieldbackground=BG_CARD,
                         rowheight=28,
                         font=("Courier New", 10))
        style.configure("Treeview.Heading",
                         background=BG_INPUT,
                         foreground=ACCENT,
                         font=("Courier New", 10, "bold"))
        style.map("Treeview", background=[("selected", ACCENT2)])

        # Create table with columns
        columns = ("port", "service", "protocol", "status", "risk", "recommendation")
        self.table = ttk.Treeview(frame, columns=columns,
                                   show="headings", height=14)

        # Define column headers and widths
        col_config = {
            "port":           ("Port",           60),
            "service":        ("Service",        110),
            "protocol":       ("Protocol",       80),
            "status":         ("Status",         85),
            "risk":           ("AI Risk",        130),
            "recommendation": ("Recommendation", 380),
        }
        for col, (heading, width) in col_config.items():
            self.table.heading(col, text=heading)
            self.table.column(col, width=width, anchor="center" if col != "recommendation" else "w")

        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical",
                                   command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)

        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # ----------------------------------------------------------
    # UI BUILDER: Threat Score Panel
    # ----------------------------------------------------------
    def _build_threat_score(self):
        """Build the overall threat score display."""
        frame = tk.Frame(self.root, bg=BG_CARD, padx=15, pady=8)
        frame.pack(fill="x", padx=20, pady=(5, 5))

        tk.Label(frame, text="🎯 Threat Score:",
                 font=("Courier New", 12, "bold"),
                 bg=BG_CARD, fg=ACCENT).pack(side="left")

        self.score_label = tk.Label(
            frame, text="— / 100",
            font=("Courier New", 14, "bold"),
            bg=BG_CARD, fg=TEXT_GREY
        )
        self.score_label.pack(side="left", padx=10)

        self.risk_label = tk.Label(
            frame, text="",
            font=("Courier New", 12, "bold"),
            bg=BG_CARD, fg=TEXT_GREY
        )
        self.risk_label.pack(side="left", padx=5)

        # Summary counters
        self.safe_count  = tk.Label(frame, text="🟢 Safe: 0",
                                     font=("Courier New", 10),
                                     bg=BG_CARD, fg=GREEN)
        self.safe_count.pack(side="right", padx=10)

        self.susp_count  = tk.Label(frame, text="🟡 Suspicious: 0",
                                     font=("Courier New", 10),
                                     bg=BG_CARD, fg=YELLOW)
        self.susp_count.pack(side="right", padx=10)

        self.dang_count  = tk.Label(frame, text="🔴 Dangerous: 0",
                                     font=("Courier New", 10),
                                     bg=BG_CARD, fg=RED)
        self.dang_count.pack(side="right", padx=10)

    # ----------------------------------------------------------
    # UI BUILDER: Status Bar
    # ----------------------------------------------------------
    def _build_status_bar(self):
        """Build the bottom status bar."""
        self.status_var = tk.StringVar(value="Ready. Enter a target IP and press Start Scan.")
        tk.Label(
            self.root,
            textvariable=self.status_var,
            font=("Courier New", 9),
            bg=BG_INPUT, fg=TEXT_GREY,
            anchor="w", padx=10
        ).pack(fill="x", side="bottom")

    # ----------------------------------------------------------
    # ACTION: Start Scan
    # ----------------------------------------------------------
    def _start_scan(self):
        """Validate inputs and begin scanning in a background thread."""
        ip = self.ip_var.get().strip()

        # Validate IP address
        if not validate_ip(ip):
            messagebox.showerror("Invalid IP", f"'{ip}' is not a valid IP address.\nExample: 192.168.1.1")
            return

        # Get the list of ports to scan
        ports = self._get_ports()
        if not ports:
            messagebox.showerror("No Ports", "Please enter valid port numbers.")
            return

        # Clear previous results
        self._clear_results()

        # Update UI state
        self.is_scanning  = True
        self.stop_flag[0] = False
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal", bg=RED)
        self.progress.start(10)
        self.status_var.set(f"⏳ Scanning {ip} — {len(ports)} ports...")

        # Run scan in background thread (so GUI doesn't freeze)
        thread = threading.Thread(
            target=self._run_scan,
            args=(ip, ports),
            daemon=True
        )
        thread.start()

    def _get_ports(self):
        """Return the list of ports based on selected mode."""
        mode = self.port_mode.get()

        if mode == "common":
            return DEFAULT_PORTS

        elif mode == "top1000":
            return list(range(1, 1001))

        elif mode == "custom":
            try:
                raw = self.custom_ports_var.get()
                # Support both comma-separated and ranges like "80-100"
                ports = []
                for part in raw.split(","):
                    part = part.strip()
                    if "-" in part:
                        start, end = part.split("-")
                        ports.extend(range(int(start), int(end)+1))
                    else:
                        ports.append(int(part))
                return sorted(set(ports))
            except Exception:
                return []

    # ----------------------------------------------------------
    # ACTION: Run Scan (runs in background thread)
    # ----------------------------------------------------------
    def _run_scan(self, ip, ports):
        """Perform the actual scan and update table."""

        def on_result(result):
            """Called for each port result — runs AI prediction and updates table."""
            # Get AI prediction
            ai_info = self.predictor.predict(
                result["port"],
                result["protocol"],
                result["status"]
            )

            # Add AI data to result dict
            result["risk_level"]     = ai_info["risk_level"]
            result["risk_label"]     = ai_info["label"]
            result["risk_emoji"]     = ai_info["emoji"]
            result["recommendation"] = ai_info["recommendation"]

            # Store full result
            self.scan_results.append(result)

            # Update the GUI table (must use after() to be thread-safe)
            self.root.after(0, self._add_table_row, result, ai_info["color"])

        # Run the scan
        scan_target(ip, ports, callback=on_result, stop_flag=self.stop_flag)

        # Scan finished — update UI on main thread
        self.root.after(0, self._scan_complete)

    # ----------------------------------------------------------
    # ACTION: Add a row to the results table
    # ----------------------------------------------------------
    def _add_table_row(self, result, color):
        """Add one scan result row to the Treeview table."""
        status_icon = {"open": "🔓 Open", "closed": "🔒 Closed", "filtered": "🛡 Filtered"}
        risk_text   = f"{result['risk_emoji']} {result['risk_label']}"

        row = (
            result["port"],
            result.get("service", "Unknown"),
            result["protocol"],
            status_icon.get(result["status"], result["status"]),
            risk_text,
            result.get("recommendation", "")[:60],  # Truncate long text
        )

        # Insert row and color-code by risk
        iid = self.table.insert("", "end", values=row)

        # Color the row based on risk level
        tag = f"risk_{result['risk_level']}"
        self.table.item(iid, tags=(tag,))
        self.table.tag_configure("risk_0", foreground=GREEN)
        self.table.tag_configure("risk_1", foreground=YELLOW)
        self.table.tag_configure("risk_2", foreground=RED)

        # Update counters
        self._update_counters()

    # ----------------------------------------------------------
    # ACTION: Update summary counters
    # ----------------------------------------------------------
    def _update_counters(self):
        """Refresh the Safe/Suspicious/Dangerous counters."""
        safe = sum(1 for r in self.scan_results if r.get("risk_level") == 0)
        susp = sum(1 for r in self.scan_results if r.get("risk_level") == 1)
        dang = sum(1 for r in self.scan_results if r.get("risk_level") == 2)
        self.safe_count.config(text=f"🟢 Safe: {safe}")
        self.susp_count.config(text=f"🟡 Suspicious: {susp}")
        self.dang_count.config(text=f"🔴 Dangerous: {dang}")

    # ----------------------------------------------------------
    # ACTION: Scan Complete
    # ----------------------------------------------------------
    def _scan_complete(self):
        """Called when scan finishes. Updates UI and shows threat score."""
        self.is_scanning = False
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled", bg=TEXT_GREY)
        self.progress.stop()

        # Calculate and show threat score
        open_results = [r for r in self.scan_results if r.get("status") == "open"]
        score = self.predictor.calculate_threat_score(open_results)
        label, color = self.predictor.get_threat_label(score)

        self.score_label.config(text=f"{score} / 100", fg=color)
        self.risk_label.config(text=f"[ {label} ]", fg=color)

        total = len(self.scan_results)
        open_count = len(open_results)
        self.status_var.set(
            f"✅ Scan complete! {total} ports scanned | "
            f"{open_count} open | Threat Score: {score}/100 — {label}"
        )

    # ----------------------------------------------------------
    # ACTION: Stop Scan
    # ----------------------------------------------------------
    def _stop_scan(self):
        """Set the stop flag to halt scanning."""
        self.stop_flag[0] = True
        self.status_var.set("⏹ Scan stopped by user.")
        self.progress.stop()
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled", bg=TEXT_GREY)

    # ----------------------------------------------------------
    # ACTION: Export to CSV
    # ----------------------------------------------------------
    def _export_results(self):
        """Save scan results to a CSV file."""
        if not self.scan_results:
            messagebox.showinfo("No Data", "No scan results to export.")
            return

        # Generate filename with timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"intelliport_scan_{timestamp}.csv"

        try:
            with open(filename, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "port", "service", "protocol",
                    "status", "risk_label", "recommendation"
                ])
                writer.writeheader()
                for r in self.scan_results:
                    writer.writerow({
                        "port":           r.get("port"),
                        "service":        r.get("service", ""),
                        "protocol":       r.get("protocol", ""),
                        "status":         r.get("status", ""),
                        "risk_label":     r.get("risk_label", ""),
                        "recommendation": r.get("recommendation", ""),
                    })
            messagebox.showinfo("Exported", f"Results saved to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    # ----------------------------------------------------------
    # ACTION: Clear Results
    # ----------------------------------------------------------
    def _clear_results(self):
        """Clear the results table and reset counters."""
        for row in self.table.get_children():
            self.table.delete(row)
        self.scan_results = []
        self.score_label.config(text="— / 100", fg=TEXT_GREY)
        self.risk_label.config(text="", fg=TEXT_GREY)
        self.safe_count.config(text="🟢 Safe: 0")
        self.susp_count.config(text="🟡 Suspicious: 0")
        self.dang_count.config(text="🔴 Dangerous: 0")
        self.status_var.set("Ready.")


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    root = tk.Tk()
    app  = IntelliPortApp(root)
    root.mainloop()
