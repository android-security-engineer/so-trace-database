"""SoTraceCollector and SO base finder — does NOT import lldb at module level."""


class SoTraceCollector:
    """Step-trace collector driven by LLDB's SBProcess/SBThread API."""

    def __init__(self, debugger, batcher, so_base: int, so_size: int,
                 max_steps: int, target_tid=None):
        self.debugger   = debugger
        self.batcher    = batcher
        self.so_base    = so_base
        self.so_size    = so_size
        self.max_steps  = max_steps
        self.target_tid = target_tid
        self.steps_done = 0
        self._prev_pc   = {}
        self._call_depth = {}

    def start(self):
        """Register threads and begin the step loop."""
        self._collect_threads()
        self._step_loop()

    def _collect_threads(self):
        import lldb
        process = self.debugger.GetSelectedTarget().GetProcess()
        for i in range(process.GetNumThreads()):
            t = process.GetThreadAtIndex(i)
            self.batcher.add_thread({
                "thread_id": int(t.GetThreadID()),
                "create_step": 0, "parent_thread_id": 0,
                "stack_base": 0, "stack_size": 0,
                "tls_addr": 0, "is_jni_attached": False,
            })

    def _step_loop(self):
        import lldb
        target  = self.debugger.GetSelectedTarget()
        process = target.GetProcess()

        # Create a private listener so we don't steal events from LLDB UI
        listener = lldb.SBListener("sotrace_stepper")
        process.GetBroadcaster().AddListener(
            listener, lldb.SBProcess.eBroadcastBitStateChanged
        )

        try:
            while self.steps_done < self.max_steps:
                state = process.GetState()
                if state not in (lldb.eStateStopped, lldb.eStateSuspended):
                    break

                self._collect_state(process)
                self.steps_done += 1

                # Issue stepi on the selected thread
                thread = process.GetSelectedThread()
                if self.target_tid is not None:
                    for i in range(process.GetNumThreads()):
                        t = process.GetThreadAtIndex(i)
                        if t.GetThreadID() == self.target_tid:
                            thread = t
                            break
                thread.StepInstruction(False)  # step into

                # Wait for the process to stop again (5s timeout)
                event = lldb.SBEvent()
                if not listener.WaitForEvent(5, event):
                    break  # timeout — process may have exited
                if not lldb.SBProcess.EventIsProcessEvent(event):
                    continue
                new_state = lldb.SBProcess.GetStateFromEvent(event)
                if new_state not in (lldb.eStateStopped, lldb.eStateSuspended):
                    break
        finally:
            process.GetBroadcaster().RemoveListener(listener)

    def _collect_state(self, process):
        try:
            thread = process.GetSelectedThread()
            tid    = int(thread.GetThreadID())
            frame  = thread.GetSelectedFrame()
            pc     = frame.GetPC()

            if self.so_base and not (self.so_base <= pc < self.so_base + self.so_size):
                return

            offset    = pc - self.so_base if self.so_base else pc
            seq       = self.batcher.next_seq()
            prev      = self._prev_pc.get(tid)
            is_branch = prev is not None and abs(pc - prev) > 8
            self._prev_pc[tid] = pc

            self.batcher.add_instruction({
                "seq": seq, "thread_id": tid,
                "address": offset,
                "is_branch": is_branch,
                "branch_taken": is_branch,
            })
        except Exception:
            pass  # never crash the step loop


def find_so_base(debugger, so_name: str):
    """
    Locate a loaded SO's base address via LLDB module info,
    falling back to /proc/<pid>/maps if the module API yields nothing.

    Returns (base_addr: int, size: int) or (0, 0).
    """
    import lldb

    target  = debugger.GetSelectedTarget()
    process = target.GetProcess()

    # Strategy 1: LLDB module API
    best_base = 0
    best_size = 0
    for i in range(target.GetNumModules()):
        mod      = target.GetModuleAtIndex(i)
        filename = mod.GetFileSpec().GetFilename() or ''
        if so_name not in filename:
            continue
        # Collect all valid section load addresses to find min/max
        addrs = []
        for j in range(mod.GetNumSections()):
            sec  = mod.GetSectionAtIndex(j)
            load = sec.GetLoadAddress(target)
            if load != lldb.LLDB_INVALID_ADDRESS and load > 0:
                addrs.append((load, sec.GetByteSize()))
        if addrs:
            min_addr = min(a for a, _ in addrs)
            max_end  = max(a + s for a, s in addrs)
            best_base = min_addr
            best_size = max_end - min_addr
            return best_base, best_size

    # Strategy 2: /proc/<pid>/maps
    try:
        pid = process.GetProcessID()
        with open(f'/proc/{pid}/maps') as f:
            for line in f:
                if so_name not in line:
                    continue
                if 'r-xp' not in line and 'r--p' not in line:
                    continue
                parts = line.split()
                start_s, end_s = parts[0].split('-')
                start = int(start_s, 16)
                end   = int(end_s,   16)
                if best_base == 0 or start < best_base:
                    best_base = start
                    best_size = end - start
    except Exception:
        pass

    return best_base, best_size
