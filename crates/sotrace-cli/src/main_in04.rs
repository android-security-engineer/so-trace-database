
fn print_producer_consumer(pcs: &[sotrace_engine::analyzer::thread_analyzer::ProducerConsumerPattern]) {
    println!("\n=== Producer-Consumer Patterns ({}) ===", pcs.len());
    for (i, p) in pcs.iter().enumerate() {
        let addrs: Vec<String> = p.shared_addresses.iter()
            .map(|a| format!("0x{:x} ({}B, xfer {}B)", a.address, a.access_size, a.overlap_size))
            .collect();
        // sync_mechanism now carries the primitive kind alongside the address,
        // so the human-readable line reports "0x.. (mutex)" instead of a bare
        // address the reverse engineer would have to cross-reference manually.
        let sync = p
            .sync_mechanism
            .as_ref()
            .map(|m| format!("0x{:x} ({:?})", m.addr, m.kind))
            .unwrap_or_else(|| "none".into());
        println!(
            "  [{}] T{} → T{}  cycles={} avg_latency={} max_latency={}  addrs=[{}]  sync={}",
            i, p.producer_thread, p.consumer_thread, p.cycle_count, p.avg_latency_steps,
            p.max_latency_steps,
            addrs.join(", "), sync
        );
    }
}

fn print_scheduling(stats: &[sotrace_engine::analyzer::thread_analyzer::ThreadSchedulingStats]) {
    println!("\n=== Thread Scheduling ({}) ===", stats.len());
    for (i, s) in stats.iter().enumerate() {
        let cores: Vec<String> = s.cpu_cores.iter().map(|c| c.to_string()).collect();
        let residency: Vec<String> = s.core_residency.iter()
            .map(|(core, steps)| format!("core{}:{}steps", core, steps))
            .collect();
        println!(
            "  [{}] T{}  in={} out={} (vol={} invol={}) migrations={}  cores=[{}]  residency=[{}]",
            i, s.thread_id, s.scheduled_in_count, s.scheduled_out_count,
            s.voluntary_switches, s.involuntary_switches, s.migration_count,
            cores.join(", "),
            residency.join(", ")
        );
    }
}

fn print_lifecycle(life: &[sotrace_engine::analyzer::thread_analyzer::ThreadLifecycleInfo]) {
    println!("\n=== Thread Lifecycle ({}) ===", life.len());
    for (i, l) in life.iter().enumerate() {
        let indent = "  ".repeat(l.tree_depth as usize);
        let parent = if l.parent_thread_id == 0 {
            "root".to_string()
        } else {
            format!("T{}", l.parent_thread_id)
        };
        let children: Vec<String> = l.child_thread_ids.iter().map(|c| format!("T{}", c)).collect();
        let lifespan = match l.lifespan {
            Some(span) => format!("{} steps", span),
            None if l.is_alive => "alive".to_string(),
            None => "unknown".to_string(),
        };
        println!(
            "  [{}] {}T{} \"{}\"  parent={} depth={} create@{} {} lifespan={}  children=[{}]",
            i, indent, l.thread_id, l.name, parent, l.tree_depth, l.create_step,
            l.exit_step.map(|e| format!("exit@{}", e)).unwrap_or_else(|| "running".to_string()),
            lifespan, children.join(", ")
        );
    }
}

fn print_thread_states(stats: &[sotrace_engine::analyzer::thread_analyzer::ThreadStateStats]) {
    println!("\n=== Thread States ({}) ===", stats.len());
    for (i, s) in stats.iter().enumerate() {
        let states: Vec<String> = s
            .time_in_state
            .iter()
            .map(|(name, steps)| format!("{}={}", name, steps))
            .collect();
        println!(
            "  [{}] T{}  transitions={} measured={} run={} wait={} blocked={:.0}% final={}  [{}]",
            i, s.thread_id, s.transition_count, s.total_measured_steps,
            s.running_steps, s.waiting_steps, s.blocked_ratio * 100.0,
            s.final_state, states.join(", ")
        );
    }
}

fn print_critical_sections(cs: &[sotrace_engine::analyzer::thread_analyzer::CriticalSectionStats]) {
    println!("\n=== Critical Sections ({}) ===", cs.len());
    for (i, c) in cs.iter().enumerate() {
        let holders: Vec<String> = c.holder_threads.iter().map(|t| format!("T{}", t)).collect();
        println!(
            "  [{}] lock=0x{:X} ({:?})  holds={} total={} avg={} max={} (T{} steps {}..{})  holders=[{}]",
            i, c.lock_address.addr, c.lock_address.kind, c.hold_count, c.total_hold_steps, c.avg_hold_steps,
            c.max_hold_steps, c.longest_hold_thread, c.longest_hold_start, c.longest_hold_end,
            holders.join(", ")
        );
    }
}

fn print_jni_boundary(stats: &[sotrace_engine::analyzer::thread_analyzer::JniBoundaryStats]) {
    println!("\n=== JNI Boundary ({}) ===", stats.len());
    for (i, s) in stats.iter().enumerate() {
        // Pair each native address with its resolved function name (if any).
        let addrs: Vec<String> = s.native_addresses.iter().zip(s.native_functions.iter())
            .map(|(a, n)| match n {
                Some(name) if !name.is_empty() => format!("0x{:X}={}", a, name),
                _ => format!("0x{:X}", a),
            })
            .collect();
        let window = match (s.first_crossing_step, s.last_crossing_step) {
            (Some(f), Some(l)) => format!("steps {}..{}", f, l),
            _ => "no crossings".to_string(),
        };
        println!(
            "  [{}] T{} attached={} crossings={} (j2n={} n2j={})  native=[{}]  java={}  window={}",
            i, s.thread_id, s.is_jni_attached, s.total_crossings,
            s.java_to_native_count, s.native_to_java_count,
            addrs.join(", "),
            s.java_methods.join(", "),
            window
        );
    }
}

