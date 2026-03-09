import os
import time
import signal
import sys
import glob
import argparse
import logging
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box

# --- CONFIGURATION ---
# Define different cgroups to monitor with varying stringency rules.
# For example, we might be more aggressive about killing user apps than system services.
CGROUP_PROFILES = {
    "User Apps": {
        "path": "/sys/fs/cgroup/user.slice",
        "thrash_threshold_ms": 100.0,  # Lower threshold (kill sooner)
        "swap_kill_threshold": 80,     # Kill if swap > 80%
        "streak_limit": 3,             # Only 3 seconds of thrashing allowed
        "cooldown_time": 5.0,
        "grace_period": 2.0
    },
    "System Services": {
        "path": "/sys/fs/cgroup/system.slice",
        "thrash_threshold_ms": 250.0,  # Higher threshold (more lenient)
        "swap_kill_threshold": 95,     # Kill if swap > 95%
        "streak_limit": 8,             # Allow 8 seconds of thrashing before action
        "cooldown_time": 15.0,
        "grace_period": 5.0
    }
}

CLK_TCK = os.sysconf(os.sysconf_names['SC_CLK_TCK'])


class ProcessStats:
    def __init__(self, pid):
        self.pid = pid
        self.cmd = "?"
        self.rss = 0
        self.swap = 0
        self.cpu_usage = 0.0
        self.last_cpu_ticks = 0
        self.alive = True
        self.oom_adj = 0
        self.oom_score = 0
        self.base_score = 0

        try:
            with open(f"/proc/{pid}/comm") as f:
                self.cmd = f.read().strip()
        except:
            pass

    def update(self, dt):
        try:
            with open(f"/proc/{self.pid}/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        self.rss = int(line.split()[1]) // 1024
                    elif line.startswith("VmSwap:"):
                        self.swap = int(line.split()[1]) // 1024

            with open(f"/proc/{self.pid}/stat") as f:
                stats = f.read().split(')')[-1].split()
                total_ticks = int(stats[11]) + int(stats[12])
                if self.last_cpu_ticks > 0 and dt > 0:
                    self.cpu_usage = ((total_ticks - self.last_cpu_ticks) / CLK_TCK) / dt * 100
                self.last_cpu_ticks = total_ticks

            with open(f"/proc/{self.pid}/oom_score_adj") as f:
                self.oom_adj = int(f.read().strip())
            with open(f"/proc/{self.pid}/oom_score") as f:
                self.oom_score = int(f.read().strip())

            self.base_score = self.oom_score - self.oom_adj

        except:
            self.alive = False


class CgroupMonitor:
    def __init__(self, name, config, global_procs):
        self.name = name
        self.path = config["path"]
        self.thrash_threshold_ms = config["thrash_threshold_ms"]
        self.swap_kill_threshold = config["swap_kill_threshold"]
        self.streak_limit = config["streak_limit"]
        self.cooldown_time = config["cooldown_time"]
        self.grace_period = config.get("grace_period", 2.0)
        self.dry_run = config.get("dry_run", False)
        
        self.global_procs = global_procs
        self.last_psi_total = self.read_psi_total()
        self.thrash_streak = 0
        self.cooldown_timer = 0.0
        self.last_kill_msg = ""
        self.pending_terms = {}
        self.active_list = []
        self.m_curr = 0
        self.s_curr = 0
        self.swap_pct = 0
        self.blocked_ms = 0
        self.oom_status_msg = "HEALTHY"

    def read_psi_total(self):
        try:
            with open(f"{self.path}/memory.pressure") as f:
                for line in f:
                    if line.startswith("full"):
                        return int(line.split("total=")[1])
        except:
            return 0
        return 0

    def get_all_pids(self):
        """Recursively find all PIDs in this cgroup and its sub-cgroups."""
        pids = []
        # Walk through all cgroup.procs files in the directory tree
        for root, dirs, files in os.walk(self.path):
            if "cgroup.procs" in files:
                try:
                    with open(os.path.join(root, "cgroup.procs")) as f:
                        for line in f:
                            pid = line.strip()
                            if pid:
                                pids.append(int(pid))
                except PermissionError:
                    pass
                except FileNotFoundError:
                    pass
        return pids

    def tick(self, dt, dry_run=False):
        # 1. Memory/Swap Stats
        try:
            with open(f"{self.path}/memory.current") as f:
                self.m_curr = int(f.read()) // 1048576
            with open(f"{self.path}/memory.swap.current") as f:
                self.s_curr = int(f.read()) // 1048576
                
            with open(f"{self.path}/memory.swap.max") as f:
                val = f.read().strip()
                swap_max_mb = 1024 if val == "max" else int(val) // (1024 * 1024)
        except:
            swap_max_mb = 1024

        self.swap_pct = (self.s_curr / swap_max_mb) * 100 if swap_max_mb > 0 else 0

        # 2. PSI Calculation
        curr_psi_total = self.read_psi_total()
        self.blocked_ms = (curr_psi_total - self.last_psi_total) / 1000.0
        self.last_psi_total = curr_psi_total

        # 3. Process Gathering
        current_pids = self.get_all_pids()
        self.active_list = []
        EXCLUDE_CMDS = {"bash", "sleep", "systemd", "sshd"}
        
        for pid in current_pids:
            if pid not in self.global_procs: 
                self.global_procs[pid] = ProcessStats(pid)
            p = self.global_procs[pid]
            p.update(dt)
            if p.alive and p.cmd not in EXCLUDE_CMDS:
                self.active_list.append(p)

        self.active_list.sort(key=lambda x: x.oom_score, reverse=True)

        self.pending_terms = {p: t for p, t in self.pending_terms.items() if p in self.global_procs and self.global_procs[p].alive}

        # 4. Controller Logic
        self.oom_status_msg = "HEALTHY"
        should_kill = False

        if self.cooldown_timer > 0:
            self.cooldown_timer -= dt
            self.thrash_streak = 0
            self.oom_status_msg = f"COOLDOWN ({self.cooldown_timer:.1f}s)"
        else:
            if self.blocked_ms > self.thrash_threshold_ms:
                self.thrash_streak += 1
                self.oom_status_msg = f"THRASHING ({self.thrash_streak}/{self.streak_limit})"
                if self.thrash_streak == 1:
                    logging.warning(f"[{self.name}] Thrashing detected. PSI: {self.blocked_ms:.1f}ms/s (> {self.thrash_threshold_ms}ms/s)")
                if self.thrash_streak >= self.streak_limit: 
                    should_kill = True
            elif self.swap_pct > self.swap_kill_threshold:
                self.oom_status_msg = f"SWAP CRIT ({self.swap_pct:.1f}%)"
                should_kill = True
            else:
                self.thrash_streak = 0
                if self.blocked_ms > 20: 
                    self.oom_status_msg = "MEM PRESSURE"

        if should_kill and self.active_list:
            victim = self.active_list[0]
            now = time.time()
            try:
                if victim.pid in self.pending_terms:
                    if now - self.pending_terms[victim.pid] >= self.grace_period:
                        if not self.dry_run: # Use self.dry_run
                            os.kill(victim.pid, signal.SIGKILL)
                        msg = f"{'[DRY RUN] ' if self.dry_run else ''}KILLED (SIGKILL) {victim.cmd} (PID {victim.pid}) - Score: {victim.oom_score}, RAM: {victim.rss}MB"
                        logging.warning(f"[{self.name}] {msg}")
                        self.last_kill_msg = msg
                        self.cooldown_timer = self.cooldown_time
                        self.thrash_streak = 0
                        del self.pending_terms[victim.pid]
                    else:
                        self.last_kill_msg = f"WAITING for {victim.cmd} grace period..."
                else:
                    if not self.dry_run: # Use self.dry_run
                        os.kill(victim.pid, signal.SIGTERM)
                    self.pending_terms[victim.pid] = now
                    msg = f"{'[DRY RUN] ' if self.dry_run else ''}TERM (SIGTERM) sent to {victim.cmd} (PID {victim.pid}) - Score: {victim.oom_score}"
                    logging.info(f"[{self.name}] {msg}")
                    self.last_kill_msg = msg
            except Exception as e:
                self.last_kill_msg = f"ERR KILL PID {victim.pid}: {e}"
                logging.error(f"[{self.name}] {self.last_kill_msg}")
                if victim.pid in self.pending_terms:
                    del self.pending_terms[victim.pid]


def parse_args():
    parser = argparse.ArgumentParser(description="Multi-Cgroup OOM Controller")
    parser.add_argument("--dry-run", action="store_true", help="Simulate killing processes without actually sending signals")
    return parser.parse_args()


def main():
    parser = argparse.ArgumentParser(description="Multi-Cgroup OOM Controller")
    parser.add_argument("--dry-run", action="store_true", help="Simulate kills without sending signals")
    args = parser.parse_args()
    
    # In dry-run mode we don't necessarily need root, but we still need to read cgroups
    if os.geteuid() != 0 and not args.dry_run:
        print("ERROR: This monitor must be run with sudo to read cgroups and kill processes.")
        sys.exit(1)

    # Setup Logging
    logging.basicConfig(
        filename='mem_monitor.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.info(f"OOM Controller Started (Dry Run: {args.dry_run})")

    global_procs = {}
    monitors = []
    
    # Initialize a monitor for each configured cgroup
    for name, config in CGROUP_PROFILES.items():
        config["dry_run"] = args.dry_run # Pass dry_run flag to config
        if os.path.exists(config["path"]):
            monitors.append(CgroupMonitor(name, config, global_procs))
        else:
            print(f"Warning: Cgroup path {config['path']} does not exist. Skipping {name}.")
            
    if not monitors:
        print("ERROR: No valid cgroup paths found to monitor.")
        sys.exit(1)

    last_time = time.time()
    console = Console()
    
    title = "[bold cyan]=== MULTI-CGROUP OOM CONTROLLER ===[/bold cyan]"
    if args.dry_run:
        title += " [bold yellow](DRY RUN MODE)[/bold yellow]"

    try:
        with Live(console=console, refresh_per_second=2) as live:
            while True:
                now = time.time()
                dt = now - last_time
                if dt < 1.0:
                    time.sleep(1.0 - dt)
                    now = time.time()
                    dt = now - last_time

                # Tick and render each monitor
                tables = []
                for m in monitors:
                    m.tick(dt, dry_run=args.dry_run)
                    
                    # Create a rich table for the monitor
                    table = Table(title=f"[bold]{m.name.upper()}[/bold] - {m.path}", expand=True, box=box.ROUNDED)
                    table.add_column("PID", justify="right", style="cyan")
                    table.add_column("CMD", style="magenta")
                    table.add_column("RSS(MB)", justify="right")
                    table.add_column("SWAP(MB)", justify="right")
                    table.add_column("SCORE", justify="right", style="red")
                    table.add_column("CPU%", justify="right")
                    table.add_column("NOTES", style="yellow")
                    
                    status_color = "green" if m.oom_status_msg == "HEALTHY" else "bold red"
                    
                    header_text = f"RULES : Kill >{m.thrash_threshold_ms}ms/s PSI for {m.streak_limit}s OR Swap >{m.swap_kill_threshold}%\n"
                    header_text += f"STATS : RAM: {m.m_curr}MB | SWAP: {m.s_curr}MB ({m.swap_pct:.1f}%) | PSI: {m.blocked_ms:.1f}ms/s\n"
                    header_text += f"STATUS: [{status_color}]{m.oom_status_msg}[/{status_color}]"
                    if m.last_kill_msg:
                        header_text += f"\nACTION: [bold yellow]{m.last_kill_msg}[/bold yellow]"
                    
                    # Show top 3 offenders in this slice
                    top_procs = m.active_list[:3]
                    
                    for p in top_procs:
                        marker = "<- NEXT VICTIM" if p == top_procs[0] and m.oom_status_msg.startswith("THRASH") else ""
                        table.add_row(
                            str(p.pid), 
                            p.cmd, 
                            str(p.rss), 
                            str(p.swap), 
                            str(p.oom_score), 
                            f"{p.cpu_usage:5.1f}%", 
                            marker
                        )
                        
                    if not top_procs:
                        table.add_row("", "No active trackable processes", "", "", "", "", "")
                        
                    panel = Panel(table, title=header_text, title_align="left", border_style="blue")
                    tables.append(panel)

                # Assemble main layout
                group = Table.grid(padding=1)
                group.add_column()
                group.add_row(title)
                for t in tables:
                    group.add_row(t)
                
                live.update(group)
                last_time = now
    except KeyboardInterrupt:
        console.print("[bold red]Exiting...[/bold red]")


if __name__ == "__main__":
    main()
