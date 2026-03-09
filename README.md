Linux User Space Memory Pressure Controller
1. Abstract & Introduction
The Problem
Traditional Linux memory management relies on the Kernel OOM Killer. However, by the time the kernel triggers a kill, the system has often entered a state of thrashing—where the CPU is 100% occupied swapping pages between RAM and disk. This leads to:

System Freezes: Unresponsive mouse, keyboard, and audio.

Late Activation: The kernel waits until memory is 100% exhausted.

Data Loss: Unsaved work is lost because the system becomes completely locked.

The Solution
This project implements a User Space Memory Manager that monitors Pressure Stall Information (PSI). Instead of waiting for 0% memory, it detects the rate of struggle (stalling). When memory pressure stays high for a sustained period, it proactively terminates the highest-scoring "unimportant" process to restore system fluidity.

2. Key Technical Concepts
PSI (Pressure Stall Information): The modern Linux "Check Engine Light." It tracks how long tasks are delayed due to a lack of memory. We monitor the full line, which indicates that all tasks are stalled.

Cgroups v2: Used to isolate the test environment. By placing memory-consuming programs in a specific cgroup, we can monitor and limit them without crashing the entire Operating System.

RSS (Resident Set Size): The portion of memory currently held in RAM.

Swap: Virtual memory on the disk. High swap usage combined with high PSI is a primary indicator of thrashing.

OOM Score Adj: A user-defined "importance" value (range -1000 to 1000). A negative value protects a process; a positive value makes it a target.

3. Project Architecture
The controller operates in a feedback loop:

Ingestion: Reads PSI stats from /proc/pressure/memory and cgroup stats from /sys/fs/cgroup.

Analysis: Calculates the Base Score (Memory Usage) and adds the ADJ (Priority).

Decision: If PSI > 150ms/s for 5 consecutive seconds, it identifies a victim.

Action: Sends SIGKILL to the process with the highest Final Score.

4. Setup & Methodology
Step 1: Prepare the Cgroup Environment
To safely demonstrate the controller, create a dedicated cgroup with a memory limit.

Bash
# Create the scope (requires sudo)
sudo mkdir -p /sys/fs/cgroup/system.slice/thrashlab.scope

# Set a 1GB limit for the demo
echo "1G" | sudo tee /sys/fs/cgroup/system.slice/thrashlab.scope/memory.max
echo "1G" | sudo tee /sys/fs/cgroup/system.slice/thrashlab.scope/memory.swap.max
Step 2: The Memory Consumer (mem.c)
Compile a simple C program that allocates memory and touches every page (to ensure it's not just "lazy" allocation).

C
// Example: mem.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    long megabytes = atol(argv[1]);
    size_t bytes = megabytes * 1024 * 1024;
    char *ptr = malloc(bytes);
    for (size_t i = 0; i < bytes; i += 4096) ptr[i] = 0; // Trigger RAM usage
    while(1) sleep(1);
    return 0;
}
Step 3: Running the Monitor
Launch the Python controller with root privileges to allow it to read /proc and send signals.

Bash
sudo python3 mem_monitor.py
5. Demonstration Steps
Phase 1: Normal Operation
Run a small memory consumer and observe the "HEALTHY" status.

Bash
# In Terminal 2:
sudo cgexec -g memory:system.slice/thrashlab.scope ./mem 200 &
Phase 2: Priority/Protection Test
Run an "important" large process (with -500 adjustment) and an "unimportant" smaller process (with +500 adjustment).

Bash
# High priority process
sudo cgexec -g memory:system.slice/thrashlab.scope ./mem 700 -500 &

# Low priority process
sudo cgexec -g memory:system.slice/thrashlab.scope ./mem 200 500 &
Observation: Note that the Final Score for the 200MB process becomes higher than the 700MB process because of the ADJ value.

Phase 3: Triggering the Killer
Run enough processes to exceed 1GB.

Bash
sudo cgexec -g memory:system.slice/thrashlab.scope ./mem 500 0 &
Observation:

PSI will spike as the system starts swapping.

The Status will change to "THRASHING (Streak: X/5)".

Once the streak hits 5, the monitor will KILL the process with the highest Final Score.

The dashboard will show "ACTION: KILLED PID XXX".
