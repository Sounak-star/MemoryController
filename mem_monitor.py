import os
import time
import signal
import sys
import argparse

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.console import Group
from rich.progress_bar import ProgressBar
from rich.layout import Layout

# --- CONFIGURATION ---
CGROUP_PATH = "/sys/fs/cgroup/system.slice/thrashlab.scope"
THRASH_THRESHOLD_MS = 150.0
CLK_TCK = os.sysconf(os.sysconf_names['SC_CLK_TCK'])

# --- OOMD CONFIGURATION ---
STREAK_LIMIT = 5
COOLDOWN_TIME = 10.0
SWAP_KILL_THRESHOLD = 85
GRACE_PERIOD = 2.0


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
        self.base_score = 0  # New attribute for base score

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

            # Calculate the base score (Kernel caps final scores at 0, so if final is 0, base is approx)
            self.base_score = self.oom_score - self.oom_adj

        except:
            self.alive = False


def read_psi_total():
    try:
        with open(f"{CGROUP_PATH}/memory.pressure") as f:
            for line in f:
                if line.startswith("full"):
                    return int(line.split("total=")[1])
    except:
        return 0
    return 0


def main():
    parser = argparse.ArgumentParser(description="OOMD Simulator")
    parser.add_argument("--dry-run", action="store_true", help="Simulate kills without sending signals")
    args = parser.parse_args()

    if os.geteuid() != 0 and not args.dry_run:
        print("ERROR: This monitor must be run with sudo to kill processes.")
        sys.exit(1)

    procs = {}
    last_psi_total = read_psi_total()
    last_time = time.time()
    thrash_streak = 0
    cooldown_timer = 0.0
    last_kill_msg = ""
    pending_terms = {}  # {pid: time_sent_sigterm}

    try:
        with open(f"{CGROUP_PATH}/memory.swap.max") as f:
            val = f.read().strip()
            swap_max_mb = 1024 if val == "max" else int(val) // (1024 * 1024)
    except:
        swap_max_mb = 1024

    console = Console()
    live = Live(console=console, auto_refresh=False)
    live.start()
    
    try:
        while True:
            now = time.time()
            dt = now - last_time
            if dt < 1.0:
                time.sleep(1.0 - dt)
                now = time.time()
                dt = now - last_time

        # 1. Cgroup Memory/Swap Stats
        try:
            with open(f"{CGROUP_PATH}/memory.current") as f:
                m_curr = int(f.read()) // 1048576
            with open(f"{CGROUP_PATH}/memory.swap.current") as f:
                s_curr = int(f.read()) // 1048576
        except:
            m_curr = s_curr = 0

        swap_pct = (s_curr / swap_max_mb) * 100 if swap_max_mb > 0 else 0

        # 2. PSI Calculation
        curr_psi_total = read_psi_total()
        blocked_ms = (curr_psi_total - last_psi_total) / 1000.0
        last_psi_total = curr_psi_total

        # 3. Process Gathering
        current_pids = []
        try:
            with open(f"{CGROUP_PATH}/cgroup.procs") as f:
                current_pids = [int(x) for x in f.read().split()]
        except:
            pass

        active_list = []
        EXCLUDE_CMDS = {"bash", "sleep"}
        for pid in current_pids:
            if pid not in procs: procs[pid] = ProcessStats(pid)
            p = procs[pid]
            p.update(dt)
            if p.alive and p.cmd not in EXCLUDE_CMDS:
                active_list.append(p)

        active_list.sort(key=lambda x: x.oom_score, reverse=True)

        pending_terms = {pid: t for pid, t in pending_terms.items() if pid in procs and procs[pid].alive}

        # 4. Controller Logic
        oom_status_msg = "HEALTHY"
        should_kill = False

        if cooldown_timer > 0:
            cooldown_timer -= dt
            thrash_streak = 0
            oom_status_msg = f"COOLDOWN ({cooldown_timer:.1f}s)"
        else:
            if blocked_ms > THRASH_THRESHOLD_MS:
                thrash_streak += 1
                oom_status_msg = f"THRASHING ({thrash_streak}/{STREAK_LIMIT})"
                if thrash_streak >= STREAK_LIMIT: should_kill = True
            elif swap_pct > SWAP_KILL_THRESHOLD:
                oom_status_msg = f"SWAP CRITICAL ({swap_pct:.1f}%)"
                should_kill = True
            else:
                thrash_streak = 0
                if blocked_ms > 20: oom_status_msg = "MEMORY PRESSURE"

        if should_kill and active_list:
            victim = active_list[0]
            try:
                if args.dry_run:
                    last_kill_msg = f"WOULD KILL [PID {victim.pid}] {victim.cmd} (Score: {victim.oom_score})"
                    cooldown_timer = COOLDOWN_TIME
                    thrash_streak = 0
                else:
                    if victim.pid in pending_terms:
                        if now - pending_terms[victim.pid] >= GRACE_PERIOD:
                            os.kill(victim.pid, signal.SIGKILL)
                            last_kill_msg = f"KILLED (SIGKILL) {victim.cmd} (PID {victim.pid})"
                            cooldown_timer = COOLDOWN_TIME
                            thrash_streak = 0
                            del pending_terms[victim.pid]
                        else:
                            last_kill_msg = f"WAITING for {victim.cmd} (PID {victim.pid}) grace period..."
                    else:
                        os.kill(victim.pid, signal.SIGTERM)
                        pending_terms[victim.pid] = now
                        last_kill_msg = f"TERM (SIGTERM) sent to {victim.cmd} (PID {victim.pid})"
            except Exception as e:
                last_kill_msg = f"ERROR KILLING {victim.pid}: {e}"
                if victim.pid in pending_terms:
                    del pending_terms[victim.pid]

        # 5. Render
        status_color = "green" if oom_status_msg == "HEALTHY" else "bold red"

        table = Table(expand=True, title="OOMD Simulator Processes")
        table.add_column("PID", justify="right", style="cyan", no_wrap=True)
        table.add_column("CMD", style="magenta")
        table.add_column("RSS(MB)", justify="right", style="green")
        table.add_column("SWAP(MB)", justify="right", style="red")
        table.add_column("BASE", justify="right", style="blue")
        table.add_column("+ ADJ", justify="right", style="yellow")
        table.add_column("= SCORE", justify="right", style="bold white")
        table.add_column("CPU%", justify="right", style="green")
        table.add_column("STATUS", justify="left", style="bold red")

        for p in active_list:
            marker = "<- NEXT VICTIM" if p == active_list[0] else ""
            table.add_row(
                str(p.pid), p.cmd, str(p.rss), str(p.swap), str(p.base_score),
                str(p.oom_adj), str(p.oom_score), f"{p.cpu_usage:5.1f}%", marker
            )

        info_text = Text()
        info_text.append(f"RAM: ", style="bold")
        info_text.append(f"{m_curr}MB ", style="green")
        info_text.append(f"| SWAP: ", style="bold")
        info_text.append(f"{s_curr}MB ", style="red")
        info_text.append(f"| PSI: ", style="bold")
        info_text.append(f"{blocked_ms:.1f}ms/s\n\n", style="yellow")

        info_text.append(f"STATUS: ", style="bold")
        info_text.append(f"{oom_status_msg}\n", style=status_color)

        if last_kill_msg:
            info_text.append(f"ACTION: {last_kill_msg}\n", style="bold blink red")

        swap_bar = ProgressBar(total=100, completed=swap_pct, width=40, style="grey50", complete_style="red")
        
        top_layout = Layout()
        top_layout.split_row(
            Layout(info_text, name="info"),
            Layout(Group(Text("SWAP Usage:", style="bold white"), swap_bar, Text(f"{swap_pct:.1f}%", style="red")), name="bar")
        )

        group = Group(
            Panel(top_layout, title="System Status", border_style="blue", height=6),
            table
        )

        live.update(group)
        live.refresh()

        last_time = now

    except KeyboardInterrupt:
        live.stop()
        print("Exiting...")
        sys.exit(0)
    except Exception as e:
        live.stop()
        raise e

if __name__ == "__main__":
    main()