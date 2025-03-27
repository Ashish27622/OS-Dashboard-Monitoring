import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil
import time
import threading
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import os

class EnhancedProcessMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Process Monitor Dashboard")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Custom styles
        self.style.configure("TFrame", background="#f5f5f5")
        self.style.configure("TLabel", background="#f5f5f5", font=('Segoe UI', 9))
        self.style.configure("Header.TLabel", font=('Segoe UI', 11, 'bold'), foreground="#333333")
        self.style.configure("Critical.TLabel", foreground="#e74c3c", font=('Segoe UI', 9, 'bold'))
        self.style.configure("Warning.TLabel", foreground="#f39c12", font=('Segoe UI', 9, 'bold'))
        self.style.configure("Normal.TLabel", foreground="#2ecc71", font=('Segoe UI', 9))
        self.style.configure("TButton", font=('Segoe UI', 9))
        self.style.configure("TNotebook", background="#f5f5f5")
        self.style.configure("TNotebook.Tab", font=('Segoe UI', 9, 'bold'))
        self.style.map("TNotebook.Tab", background=[("selected", "#3498db"), ("active", "#2980b9")])
        
        # Create main container
        self.main_container = ttk.Frame(root)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_process_tab()
        self.create_performance_tab()
        self.create_log_tab()
        
        # Initialize data
        self.process_data = []
        self.cpu_history = []
        self.mem_history = []
        self.max_history_points = 60  # Store 60 data points (1 minute at 1-second intervals)
        self.log_messages = []
        
        # Start monitoring threads
        self.running = True
        self.update_thread = threading.Thread(target=self.update_metrics, daemon=True)
        self.update_thread.start()
        
        # Initial update
        self.update_process_list()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def create_dashboard_tab(self):
        """Create the dashboard tab with system overview"""
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        
        # System info frame
        sys_info_frame = ttk.LabelFrame(self.dashboard_tab, text="System Information", padding=(10, 5))
        sys_info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # CPU info
        cpu_frame = ttk.Frame(sys_info_frame)
        cpu_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(cpu_frame, text="CPU Usage:", style="Header.TLabel").pack(side=tk.LEFT)
        self.cpu_label = ttk.Label(cpu_frame, text="0%", style="Normal.TLabel")
        self.cpu_label.pack(side=tk.LEFT, padx=5)
        self.cpu_bar = ttk.Progressbar(cpu_frame, length=200, mode='determinate')
        self.cpu_bar.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        # CPU cores
        self.core_labels = []
        cores_frame = ttk.Frame(sys_info_frame)
        cores_frame.pack(fill=tk.X, pady=2)
        ttk.Label(cores_frame, text="CPU Cores:", style="Header.TLabel").pack(side=tk.LEFT)
        for i in range(psutil.cpu_count()):
            core_frame = ttk.Frame(cores_frame)
            core_frame.pack(side=tk.LEFT, padx=2)
            ttk.Label(core_frame, text=f"C{i+1}:").pack(side=tk.LEFT)
            lbl = ttk.Label(core_frame, text="0%", style="Normal.TLabel")
            lbl.pack(side=tk.LEFT)
            self.core_labels.append(lbl)
        
        # Memory info
        mem_frame = ttk.Frame(sys_info_frame)
        mem_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(mem_frame, text="Memory Usage:", style="Header.TLabel").pack(side=tk.LEFT)
        self.mem_label = ttk.Label(mem_frame, text="0/0 MB (0%)", style="Normal.TLabel")
        self.mem_label.pack(side=tk.LEFT, padx=5)
        self.mem_bar = ttk.Progressbar(mem_frame, length=200, mode='determinate')
        self.mem_bar.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        # Disk info
        disk_frame = ttk.Frame(sys_info_frame)
        disk_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(disk_frame, text="Disk Usage (C:):", style="Header.TLabel").pack(side=tk.LEFT)
        self.disk_label = ttk.Label(disk_frame, text="0/0 GB (0%)", style="Normal.TLabel")
        self.disk_label.pack(side=tk.LEFT, padx=5)
        self.disk_bar = ttk.Progressbar(disk_frame, length=200, mode='determinate')
        self.disk_bar.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        # Network info
        net_frame = ttk.Frame(sys_info_frame)
        net_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(net_frame, text="Network:", style="Header.TLabel").pack(side=tk.LEFT)
        self.net_sent_label = ttk.Label(net_frame, text="↑ 0 KB/s", style="Normal.TLabel")
        self.net_sent_label.pack(side=tk.LEFT, padx=5)
        self.net_recv_label = ttk.Label(net_frame, text="↓ 0 KB/s", style="Normal.TLabel")
        self.net_recv_label.pack(side=tk.LEFT, padx=5)
        
        # Performance charts
        charts_frame = ttk.Frame(self.dashboard_tab)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # CPU chart
        cpu_chart_frame = ttk.Frame(charts_frame)
        cpu_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)
        
        self.cpu_fig = plt.Figure(figsize=(5, 3), dpi=80)
        self.cpu_ax = self.cpu_fig.add_subplot(111)
        self.cpu_ax.set_title('CPU Usage (%)')
        self.cpu_ax.set_ylim(0, 100)
        self.cpu_line, = self.cpu_ax.plot([], [], 'r-')
        self.cpu_canvas = FigureCanvasTkAgg(self.cpu_fig, master=cpu_chart_frame)
        self.cpu_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Memory chart
        mem_chart_frame = ttk.Frame(charts_frame)
        mem_chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)
        
        self.mem_fig = plt.Figure(figsize=(5, 3), dpi=80)
        self.mem_ax = self.mem_fig.add_subplot(111)
        self.mem_ax.set_title('Memory Usage (%)')
        self.mem_ax.set_ylim(0, 100)
        self.mem_line, = self.mem_ax.plot([], [], 'b-')
        self.mem_canvas = FigureCanvasTkAgg(self.mem_fig, master=mem_chart_frame)
        self.mem_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_process_tab(self):
        """Create the process management tab"""
        self.process_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.process_tab, text="Processes")
        
        # Process controls frame
        controls_frame = ttk.Frame(self.process_tab)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Search box
        search_frame = ttk.Frame(controls_frame)
        search_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.search_entry.bind('<KeyRelease>', self.filter_processes)
        
        # Buttons
        button_frame = ttk.Frame(controls_frame)
        button_frame.pack(side=tk.RIGHT)
        
        self.refresh_btn = ttk.Button(button_frame, text="🔄 Refresh", command=self.update_process_list)
        self.refresh_btn.pack(side=tk.LEFT, padx=2)
        
        self.end_btn = ttk.Button(button_frame, text="⛔ End Process", command=self.end_process)
        self.end_btn.pack(side=tk.LEFT, padx=2)
        
        self.details_btn = ttk.Button(button_frame, text="🔍 Details", command=self.show_process_details)
        self.details_btn.pack(side=tk.LEFT, padx=2)
        
        # Process treeview with scrollbars
        tree_frame = ttk.Frame(self.process_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        
        # Create horizontal scrollbar
        hscroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Create vertical scrollbar
        vscroll = ttk.Scrollbar(tree_frame)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Create the treeview
        self.tree = ttk.Treeview(tree_frame, columns=(
            "PID", "Name", "Status", "CPU", "Memory", "Threads", "User"
        ), show="headings", xscrollcommand=hscroll.set, yscrollcommand=vscroll.set)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Configure scrollbars
        hscroll.config(command=self.tree.xview)
        vscroll.config(command=self.tree.yview)
        
        # Configure columns
        columns = {
            "PID": {"width": 70, "anchor": tk.CENTER},
            "Name": {"width": 200, "anchor": tk.W},
            "Status": {"width": 80, "anchor": tk.CENTER},
            "CPU": {"width": 80, "anchor": tk.CENTER},
            "Memory": {"width": 100, "anchor": tk.CENTER},
            "Threads": {"width": 70, "anchor": tk.CENTER},
            "User": {"width": 120, "anchor": tk.W}
        }
        
        for col, settings in columns.items():
            self.tree.heading(col, text=col)
            self.tree.column(col, width=settings["width"], anchor=settings["anchor"])
        
        # Sort functionality
        for col in columns:
            self.tree.heading(col, command=lambda c=col: self.sort_treeview(c))
        
        # Add tag for alternate row colors
        self.tree.tag_configure('oddrow', background='#f9f9f9')
        self.tree.tag_configure('evenrow', background='#ffffff')
        
        # Add right-click menu
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.context_menu = tk.Menu(self.tree, tearoff=0)
        self.context_menu.add_command(label="End Process", command=self.end_process)
        self.context_menu.add_command(label="Process Details", command=self.show_process_details)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Refresh", command=self.update_process_list)
    
    def create_performance_tab(self):
        """Create the performance tab with detailed metrics"""
        self.performance_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.performance_tab, text="Performance")
        
        # CPU details
        cpu_frame = ttk.LabelFrame(self.performance_tab, text="CPU Details", padding=(10, 5))
        cpu_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # CPU info grid
        info_frame = ttk.Frame(cpu_frame)
        info_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(info_frame, text="Physical Cores:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.phys_cores_label = ttk.Label(info_frame, text=str(psutil.cpu_count(logical=False)))
        self.phys_cores_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(info_frame, text="Logical Cores:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.log_cores_label = ttk.Label(info_frame, text=str(psutil.cpu_count(logical=True)))
        self.log_cores_label.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        ttk.Label(info_frame, text="Max Frequency:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.max_freq_label = ttk.Label(info_frame, text=f"{psutil.cpu_freq().max:.2f} MHz")
        self.max_freq_label.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(info_frame, text="Current Frequency:").grid(row=1, column=2, sticky=tk.W, padx=5)
        self.curr_freq_label = ttk.Label(info_frame, text="0 MHz")
        self.curr_freq_label.grid(row=1, column=3, sticky=tk.W, padx=5)
        
        ttk.Label(info_frame, text="Min Frequency:").grid(row=2, column=0, sticky=tk.W, padx=5)
        self.min_freq_label = ttk.Label(info_frame, text=f"{psutil.cpu_freq().min:.2f} MHz")
        self.min_freq_label.grid(row=2, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(info_frame, text="Average Load (15min):").grid(row=2, column=2, sticky=tk.W, padx=5)
        self.avg_load_label = ttk.Label(info_frame, text="0.00")
        self.avg_load_label.grid(row=2, column=3, sticky=tk.W, padx=5)
        
        # Memory details
        mem_frame = ttk.LabelFrame(self.performance_tab, text="Memory Details", padding=(10, 5))
        mem_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Memory info grid
        mem_info_frame = ttk.Frame(mem_frame)
        mem_info_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(mem_info_frame, text="Total:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.total_mem_label = ttk.Label(mem_info_frame, text="0 GB")
        self.total_mem_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(mem_info_frame, text="Available:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.avail_mem_label = ttk.Label(mem_info_frame, text="0 GB")
        self.avail_mem_label.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        ttk.Label(mem_info_frame, text="Used:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.used_mem_label = ttk.Label(mem_info_frame, text="0 GB")
        self.used_mem_label.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(mem_info_frame, text="Free:").grid(row=1, column=2, sticky=tk.W, padx=5)
        self.free_mem_label = ttk.Label(mem_info_frame, text="0 GB")
        self.free_mem_label.grid(row=1, column=3, sticky=tk.W, padx=5)
        
        ttk.Label(mem_info_frame, text="Swap Total:").grid(row=2, column=0, sticky=tk.W, padx=5)
        self.swap_total_label = ttk.Label(mem_info_frame, text="0 GB")
        self.swap_total_label.grid(row=2, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(mem_info_frame, text="Swap Used:").grid(row=2, column=2, sticky=tk.W, padx=5)
        self.swap_used_label = ttk.Label(mem_info_frame, text="0 GB")
        self.swap_used_label.grid(row=2, column=3, sticky=tk.W, padx=5)
        
        # Disk details
        disk_frame = ttk.LabelFrame(self.performance_tab, text="Disk Details", padding=(10, 5))
        disk_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Disk treeview
        self.disk_tree = ttk.Treeview(disk_frame, columns=(
            "Device", "Mount", "Type", "Total", "Used", "Free", "Percent"
        ), show="headings", height=4)
        
        self.disk_tree.pack(fill=tk.X, pady=5)
        
        # Configure columns
        disk_columns = {
            "Device": {"width": 100, "anchor": tk.W},
            "Mount": {"width": 150, "anchor": tk.W},
            "Type": {"width": 100, "anchor": tk.W},
            "Total": {"width": 100, "anchor": tk.CENTER},
            "Used": {"width": 100, "anchor": tk.CENTER},
            "Free": {"width": 100, "anchor": tk.CENTER},
            "Percent": {"width": 80, "anchor": tk.CENTER}
        }
        
        for col, settings in disk_columns.items():
            self.disk_tree.heading(col, text=col)
            self.disk_tree.column(col, width=settings["width"], anchor=settings["anchor"])
        
        # Update disk info
        self.update_disk_info()
    
    def create_log_tab(self):
        """Create the log tab for system messages"""
        self.log_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.log_tab, text="Log")
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(
            self.log_tab, wrap=tk.WORD, width=100, height=25,
            font=('Consolas', 9), bg='#ffffff', fg='#333333'
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)
        
        # Log controls
        log_controls = ttk.Frame(self.log_tab)
        log_controls.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(log_controls, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT)
        ttk.Button(log_controls, text="Save Log", command=self.save_log).pack(side=tk.LEFT, padx=5)
    
    def update_metrics(self):
        """Continuously update system metrics"""
        net_io = psutil.net_io_counters()
        last_sent = net_io.bytes_sent
        last_recv = net_io.bytes_recv
        
        while self.running:
            try:
                # CPU metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                cpu_percents = psutil.cpu_percent(interval=1, percpu=True)
                
                # Memory metrics
                mem = psutil.virtual_memory()
                swap = psutil.swap_memory()
                
                # Disk metrics
                disk = psutil.disk_usage('/')
                
                # Network metrics
                net_io = psutil.net_io_counters()
                sent_speed = (net_io.bytes_sent - last_sent) / 1024  # KB/s
                recv_speed = (net_io.bytes_recv - last_recv) / 1024  # KB/s
                last_sent = net_io.bytes_sent
                last_recv = net_io.bytes_recv
                
                # CPU frequency
                try:
                    cpu_freq = psutil.cpu_freq().current
                except:
                    cpu_freq = 0
                
                # Update UI in main thread
                self.root.after(0, self.update_ui, {
                    'cpu_percent': cpu_percent,
                    'cpu_percents': cpu_percents,
                    'cpu_freq': cpu_freq,
                    'mem': mem,
                    'swap': swap,
                    'disk': disk,
                    'sent_speed': sent_speed,
                    'recv_speed': recv_speed
                })
                
                # Update history
                self.update_history(cpu_percent, mem.percent)
                
                time.sleep(1)
            except Exception as e:
                self.log_message(f"Error in update thread: {str(e)}", "error")
                time.sleep(5)
    
    def update_ui(self, metrics):
        """Update the UI with new metrics"""
        # CPU
        cpu_percent = metrics['cpu_percent']
        self.cpu_label.config(text=f"{cpu_percent}%")
        self.cpu_bar['value'] = cpu_percent
        
        if cpu_percent > 90:
            self.cpu_label.config(style="Critical.TLabel")
        elif cpu_percent > 70:
            self.cpu_label.config(style="Warning.TLabel")
        else:
            self.cpu_label.config(style="Normal.TLabel")
        
        # CPU cores
        for i, percent in enumerate(metrics['cpu_percents']):
            self.core_labels[i].config(text=f"{percent}%")
            if percent > 90:
                self.core_labels[i].config(style="Critical.TLabel")
            elif percent > 70:
                self.core_labels[i].config(style="Warning.TLabel")
            else:
                self.core_labels[i].config(style="Normal.TLabel")
        
        # Memory
        mem = metrics['mem']
        mem_text = f"{mem.used//1024//1024}/{mem.total//1024//1024} MB ({mem.percent}%)"
        self.mem_label.config(text=mem_text)
        self.mem_bar['value'] = mem.percent
        
        if mem.percent > 90:
            self.mem_label.config(style="Critical.TLabel")
        elif mem.percent > 70:
            self.mem_label.config(style="Warning.TLabel")
        else:
            self.mem_label.config(style="Normal.TLabel")
        
        # Disk
        disk = metrics['disk']
        disk_text = f"{disk.used//1024//1024//1024}/{disk.total//1024//1024//1024} GB ({disk.percent}%)"
        self.disk_label.config(text=disk_text)
        self.disk_bar['value'] = disk.percent
        
        if disk.percent > 90:
            self.disk_label.config(style="Critical.TLabel")
        elif disk.percent > 70:
            self.disk_label.config(style="Warning.TLabel")
        else:
            self.disk_label.config(style="Normal.TLabel")
        
        # Network
        self.net_sent_label.config(text=f"↑ {metrics['sent_speed']:.1f} KB/s")
        self.net_recv_label.config(text=f"↓ {metrics['recv_speed']:.1f} KB/s")
        
        # Performance tab updates
        self.curr_freq_label.config(text=f"{metrics['cpu_freq']:.2f} MHz")
        self.avg_load_label.config(text=f"{psutil.getloadavg()[2]:.2f}")
        
        # Memory details
        self.total_mem_label.config(text=f"{mem.total//1024//1024//1024} GB")
        self.avail_mem_label.config(text=f"{mem.available//1024//1024//1024} GB")
        self.used_mem_label.config(text=f"{mem.used//1024//1024//1024} GB")
        self.free_mem_label.config(text=f"{mem.free//1024//1024//1024} GB")
        
        # Swap details
        swap = metrics['swap']
        self.swap_total_label.config(text=f"{swap.total//1024//1024//1024} GB")
        self.swap_used_label.config(text=f"{swap.used//1024//1024//1024} GB")
    
    def update_history(self, cpu_percent, mem_percent):
        """Update the history data for charts"""
        self.cpu_history.append(cpu_percent)
        self.mem_history.append(mem_percent)
        
        # Limit history size
        if len(self.cpu_history) > self.max_history_points:
            self.cpu_history.pop(0)
            self.mem_history.pop(0)
        
        # Update charts
        self.update_charts()
    
    def update_charts(self):
        """Update the performance charts"""
        # CPU chart
        self.cpu_line.set_data(range(len(self.cpu_history)), self.cpu_history)
        self.cpu_ax.set_xlim(0, len(self.cpu_history))
        self.cpu_ax.relim()
        self.cpu_ax.autoscale_view(scaley=False)
        self.cpu_canvas.draw()
        
        # Memory chart
        self.mem_line.set_data(range(len(self.mem_history)), self.mem_history)
        self.mem_ax.set_xlim(0, len(self.mem_history))
        self.mem_ax.relim()
        self.mem_ax.autoscale_view(scaley=False)
        self.mem_canvas.draw()
    
    def update_process_list(self):
        """Update the process list"""
        try:
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Get process data
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_info', 'num_threads', 'username']):
                try:
                    processes.append((
                        proc.info['pid'],
                        proc.info['name'],
                        proc.info['status'],
                        proc.info['cpu_percent'],
                        proc.info['memory_info'].rss // 1024 // 1024,  # MB
                        proc.info['num_threads'],
                        proc.info['username'] or 'SYSTEM'
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Store process data for filtering/sorting
            self.process_data = processes
            
            # Sort by memory usage (descending) by default
            processes.sort(key=lambda x: x[4], reverse=True)
            
            # Add to treeview with alternating colors
            for i, (pid, name, status, cpu, mem, threads, user) in enumerate(processes[:500]):  # Limit to 500
                tags = ('evenrow',) if i % 2 == 0 else ('oddrow',)
                self.tree.insert("", tk.END, values=(
                    pid, name, status, f"{cpu:.1f}%", f"{mem} MB", threads, user
                ), tags=tags)
            
            self.log_message(f"Process list updated with {len(processes)} processes", "info")
        except Exception as e:
            self.log_message(f"Error updating process list: {str(e)}", "error")
    
    def update_disk_info(self):
        """Update disk information"""
        try:
            # Clear existing items
            for item in self.disk_tree.get_children():
                self.disk_tree.delete(item)
            
            # Get disk partitions
            partitions = psutil.disk_partitions()
            
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    
                    self.disk_tree.insert("", tk.END, values=(
                        partition.device,
                        partition.mountpoint,
                        partition.fstype,
                        f"{usage.total//1024//1024//1024} GB",
                        f"{usage.used//1024//1024//1024} GB",
                        f"{usage.free//1024//1024//1024} GB",
                        f"{usage.percent}%"
                    ))
                except Exception as e:
                    self.log_message(f"Error getting disk info for {partition.mountpoint}: {str(e)}", "error")
        except Exception as e:
            self.log_message(f"Error updating disk info: {str(e)}", "error")
    
    def filter_processes(self, event=None):
        """Filter processes based on search text"""
        search_text = self.search_var.get().lower()
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Filter and add matching processes
        filtered = [p for p in self.process_data if search_text in p[1].lower() or search_text in str(p[0])]
        
        for i, (pid, name, status, cpu, mem, threads, user) in enumerate(filtered[:500]):  # Limit to 500
            tags = ('evenrow',) if i % 2 == 0 else ('oddrow',)
            self.tree.insert("", tk.END, values=(
                pid, name, status, f"{cpu:.1f}%", f"{mem} MB", threads, user
            ), tags=tags)
    
    def sort_treeview(self, col):
        """Sort treeview by column"""
        # Get current sort order
        current_sort = self.tree.heading(col)['command']
        
        # Determine new sort order
        if current_sort and 'reverse' in current_sort:
            reverse = not current_sort.endswith('reverse=True)')
        else:
            reverse = False
        
        # Sort the data
        if col == "PID":
            self.process_data.sort(key=lambda x: x[0], reverse=reverse)
        elif col == "Name":
            self.process_data.sort(key=lambda x: x[1].lower(), reverse=reverse)
        elif col == "Status":
            self.process_data.sort(key=lambda x: x[2], reverse=reverse)
        elif col == "CPU":
            self.process_data.sort(key=lambda x: x[3], reverse=reverse)
        elif col == "Memory":
            self.process_data.sort(key=lambda x: x[4], reverse=reverse)
        elif col == "Threads":
            self.process_data.sort(key=lambda x: x[5], reverse=reverse)
        elif col == "User":
            self.process_data.sort(key=lambda x: x[6], reverse=reverse)
        
        # Update the treeview
        for i, (pid, name, status, cpu, mem, threads, user) in enumerate(self.process_data[:500]):
            tags = ('evenrow',) if i % 2 == 0 else ('oddrow',)
            if i < len(self.tree.get_children()):
                self.tree.item(self.tree.get_children()[i], values=(
                    pid, name, status, f"{cpu:.1f}%", f"{mem} MB", threads, user
                ), tags=tags)
            else:
                self.tree.insert("", tk.END, values=(
                    pid, name, status, f"{cpu:.1f}%", f"{mem} MB", threads, user
                ), tags=tags)
        
        # Update the heading to show sort direction
        for c in self.tree["columns"]:
            self.tree.heading(c, command=lambda _c=c: self.sort_treeview(_c))
        
        arrow = " ↓" if reverse else " ↑"
        self.tree.heading(col, text=col + arrow, command=f"lambda: self.sort_treeview('{col}', reverse={not reverse})")
    
    def end_process(self):
        """End the selected process"""
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a process to end")
            return
        
        item = self.tree.item(selected)
        pid = item['values'][0]
        name = item['values'][1]
        
        confirm = messagebox.askyesno(
            "Confirm Process Termination",
            f"Are you sure you want to end process:\n\n{name} (PID: {pid})?",
            icon='warning'
        )
        
        if confirm:
            try:
                p = psutil.Process(pid)
                p.terminate()
                self.log_message(f"Process terminated: {name} (PID: {pid})", "warning")
                self.update_process_list()
            except psutil.NoSuchProcess:
                messagebox.showerror("Error", "The process does not exist")
                self.log_message(f"Failed to terminate process: {name} (PID: {pid}) - Process not found", "error")
            except psutil.AccessDenied:
                messagebox.showerror("Error", "Access denied. Try running as Administrator.")
                self.log_message(f"Failed to terminate process: {name} (PID: {pid}) - Access denied", "error")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to end process: {str(e)}")
                self.log_message(f"Failed to terminate process: {name} (PID: {pid}) - {str(e)}", "error")
    
    def show_process_details(self):
        """Show detailed information about the selected process"""
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a process")
            return
        
        item = self.tree.item(selected)
        pid = item['values'][0]
        name = item['values'][1]
        
        try:
            p = psutil.Process(pid)
            with p.oneshot():  # Optimize by fetching all info at once
                info = {
                    "PID": pid,
                    "Name": name,
                    "Status": p.status(),
                    "CPU Percent": f"{p.cpu_percent():.1f}%",
                    "Memory RSS": f"{p.memory_info().rss//1024//1024} MB",
                    "Memory VMS": f"{p.memory_info().vms//1024//1024} MB",
                    "Threads": p.num_threads(),
                    "User": p.username(),
                    "Create Time": datetime.fromtimestamp(p.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                    "Executable": p.exe(),
                    "Working Dir": p.cwd(),
                    "Command Line": ' '.join(p.cmdline()) if p.cmdline() else 'N/A',
                    "Parent PID": p.ppid(),
                    "Children": len(p.children()),
                    "Open Files": len(p.open_files()) if p.open_files() else 0,
                    "Connections": len(p.connections()) if p.connections() else 0
                }
            
            # Create details window
            details_win = tk.Toplevel(self.root)
            details_win.title(f"Process Details - {name} (PID: {pid})")
            details_win.geometry("600x500")
            
            # Create text widget for details
            text = tk.Text(details_win, wrap=tk.WORD, font=('Consolas', 10))
            text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Insert process info
            for key, value in info.items():
                text.insert(tk.END, f"{key:>15}: {value}\n")
            
            text.config(state=tk.DISABLED)
            
            # Add close button
            ttk.Button(details_win, text="Close", command=details_win.destroy).pack(pady=5)
            
            self.log_message(f"Viewed details for process: {name} (PID: {pid})", "info")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get process details: {str(e)}")
            self.log_message(f"Failed to get details for process: {name} (PID: {pid}) - {str(e)}", "error")
    
    def show_context_menu(self, event):
        """Show right-click context menu"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def log_message(self, message, level="info"):
        """Add a message to the log"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"
        
        # Add to log messages list
        self.log_messages.append((timestamp, level, message))
        
        # Update log text widget
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_entry)
        
        # Color code based on level
        if level == "error":
            self.log_text.tag_add("error", f"end-{len(log_entry)+1}c", "end-1c")
            self.log_text.tag_config("error", foreground="red")
        elif level == "warning":
            self.log_text.tag_add("warning", f"end-{len(log_entry)+1}c", "end-1c")
            self.log_text.tag_config("warning", foreground="orange")
        
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def clear_log(self):
        """Clear the log messages"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.log_messages = []
        self.log_message("Log cleared", "info")
    
    def save_log(self):
        """Save the log to a file"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"process_monitor_log_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                for timestamp, level, message in self.log_messages:
                    f.write(f"[{timestamp}] {message}\n")
            
            self.log_message(f"Log saved to {filename}", "info")
            messagebox.showinfo("Log Saved", f"Log successfully saved to:\n{os.path.abspath(filename)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log: {str(e)}")
            self.log_message(f"Failed to save log: {str(e)}", "error")
    
    def on_close(self):
        """Handle window close event"""
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = EnhancedProcessMonitor(root)
    root.mainloop()
