import os
import time
import signal
import sys

# --- CONFIGURATION ---
CGROUP_PATH = "/sys/fs/cgroup/system.slice/thrashlab.scope"
THRASH_THRESHOLD_MS = 150.0
CLK_TCK = os.sysconf(os.sysconf_names['SC_CLK_TCK'])

# --- OOMD CONFIGURATION ---
STREAK_LIMIT = 5
COOLDOWN_TIME = 10.0
SWAP_KILL_THRESHOLD = 85


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
    if os.geteuid() != 0:
        print("ERROR: This monitor must be run with sudo to kill processes.")
        sys.exit(1)

    procs = {}
    last_psi_total = read_psi_total()
    last_time = time.time()
    thrash_streak = 0
    cooldown_timer = 0.0
    last_kill_msg = ""

    try:
        with open(f"{CGROUP_PATH}/memory.swap.max") as f:
            val = f.read().strip()
            swap_max_mb = 1024 if val == "max" else int(val) // (1024 * 1024)
    except:
        swap_max_mb = 1024

    while True:
        now = time.time()
        dt = now - last_time
        if dt < 1.0:
            time.sleep(1.0 - dt)
            now = time.time();
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
                os.kill(victim.pid, signal.SIGKILL)
                last_kill_msg = f"KILLED {victim.cmd} (PID {victim.pid}, Final Score {victim.oom_score})"
                cooldown_timer = COOLDOWN_TIME
                thrash_streak = 0
            except Exception as e:
                last_kill_msg = f"ERROR KILLING {victim.pid}: {e}"

        # 5. Render
        os.system("clear")
        print(f"=== OOMD SIMULATOR ===")
        print(f"RAM: {m_curr}MB | SWAP: {s_curr}MB ({swap_pct:.1f}%) | PSI: {blocked_ms:.1f}ms/s")
        print(f"STATUS: {oom_status_msg}")
        if last_kill_msg: print(f"ACTION: {last_kill_msg}")
        print("-" * 85)

        # Updated headers to show the math!
        print(f"{'PID':<7} {'CMD':<8} {'RSS(MB)':<8} {'SWAP(MB)':<9} {'BASE':<6} {'+ ADJ':<6} {'= SCORE':<8} {'CPU%'}")

        for p in active_list:
            marker = "<- NEXT VICTIM" if p == active_list[0] else ""

            # Formatted to clearly show BASE + ADJ = SCORE
            print(
                f"{p.pid:<7} {p.cmd:<8} {p.rss:<8} {p.swap:<9} {p.base_score:<6} {p.oom_adj:<6} {p.oom_score:<8} {p.cpu_usage:5.1f}% {marker}")

        last_time = now


if __name__ == "__main__":
    main()