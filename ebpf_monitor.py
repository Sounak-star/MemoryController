import os
import time
import signal
import sys

from rich.console import Console
from rich.live import Live
from rich.table import Table

# Attempt to import bcc (BPF Compiler Collection)
try:
    from bcc import BPF
except ImportError:
    print("ERROR: bcc module not found.")
    print("Please install it. On Ubuntu/Debian: sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc")
    sys.exit(1)

# --- eBPF C PROGRAM ---
# This eBPF program hooks into the kernel's 'shrink_node' function.
# The kernel calls this function constantly when it's under memory pressure 
# and desperately trying to scan and reclaim memory pages from processes.
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// A hash map to count the number of times shrink_node is called, grouped by PID
BPF_HASH(reclaim_counts, u32, u64);

int trace_shrink_node(struct pt_regs *ctx) {
    // Get the process ID (PID) currently running on the CPU
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Increment the count in our hash map
    u64 *val, zero = 0;
    val = reclaim_counts.lookup_or_try_init(&pid, &zero);
    if (val) {
        (*val)++;
    }
    
    return 0;
}
"""

def main():
    if os.geteuid() != 0:
        print("ERROR: eBPF scripts must be run as root (sudo).")
        sys.exit(1)

    print("Compiling eBPF program and injecting into kernel...")
    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print(f"Failed to compile eBPF program: {e}")
        sys.exit(1)
        
    # Attach our trace_shrink_node function to the kernel's shrink_node kprobe
    try:
        b.attach_kprobe(event="shrink_node", fn_name="trace_shrink_node")
    except Exception as e:
        print(f"Failed to attach to shrink_node: {e}")
        print("Note: Your kernel might use a different name for memory reclaim (like shrink_node_memcgs).")
        sys.exit(1)

    print("Successfully attached eBPF kprobe.")
    print("Monitoring real-time Kernel Memory Reclaim activity... (Press Ctrl-C to exit)\n")
    print(f"{'PID':<10} {'CMD':<16} {'RECLAIM CALLS/sec':<20} {'STATUS'}")
    print("-" * 65)

    RECLAIM_THRESHOLD = 500  # How many reclaims/sec is considered thrashing

    console = Console()
    live = Live(console=console, auto_refresh=False)
    live.start()

    try:
        while True:
            # Sleep for 1 second. During this time, the eBPF program running in 
            # kernel space is silently counting events into the 'reclaim_counts' map.
            time.sleep(1.0)
            
            reclaims = b.get_table("reclaim_counts")
            
            table = Table(title="eBPF REAL-TIME KERNEL MEMORY MONITOR", expand=True)
            table.add_column("PID", style="cyan", justify="right")
            table.add_column("CMD", style="magenta")
            table.add_column("RECLAIM CALLS/sec", justify="right", style="yellow")
            table.add_column("STATUS", style="bold red")

            ordered_procs = []
            
            for k, v in reclaims.items():
                pid = k.value
                reclaim_count = v.value
                
                # Try to resolve the binary name
                cmd = "?"
                try:
                    with open(f"/proc/{pid}/comm") as f:
                        cmd = f.read().strip()
                except FileNotFoundError:
                    cmd = "<dead>"
                    
                ordered_procs.append((pid, cmd, reclaim_count))
            
            # Sort by highest reclaim activity
            ordered_procs.sort(key=lambda x: x[2], reverse=True)
            
            for pid, cmd, count in ordered_procs:
                status = ""
                status_style = ""
                if count > RECLAIM_THRESHOLD:
                    status = "HIGH PRESSURE! (Pre-Thrashing)"
                    status_style = "bold red"
                elif count > 50:
                    status = "Elevated"
                    status_style = "yellow"
                    
                table.add_row(str(pid), cmd, str(count), f"[{status_style}]{status}[/{status_style}]" if status else "")
                
            # Clear the map for the next second's interval
            reclaims.clear()

            if len(ordered_procs) > 0:
                live.update(table)
                live.refresh()

    except KeyboardInterrupt:
        live.stop()
        print("\nDetaching kprobes and exiting...")
    except Exception as e:
        live.stop()
        raise e

if __name__ == "__main__":
    main()
