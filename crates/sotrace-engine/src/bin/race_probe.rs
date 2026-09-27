//! Race-detector scaling probe: feed N shared-address memory accesses across 3
//! threads (pure write/read pairs, no sync), time `detect_race_conditions`.
//! Usage: race_probe <events_per_scale...>  (e.g. race_probe 2000 5000 10000)

use std::time::Instant;

use sotrace_core::models::thread::ThreadInfo;
use sotrace_engine::analyzer::ThreadAnalyzer;

fn thread_info(t: u32) -> ThreadInfo {
    ThreadInfo {
        thread_id: t,
        pthread_id: Some(t as u64),
        parent_thread_id: 0,
        create_step: 0,
        exit_step: None,
        name: Some(format!("t{}", t)),
        stack_base: 0x7f000000,
        stack_size: 0x4000,
        tls_addr: 0x7f800000,
        is_jni_attached: false,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scales: Vec<usize> = if args.len() > 1 {
        args[1..].iter().map(|s| s.parse().unwrap()).collect()
    } else {
        vec![2000, 5000, 10000]
    };
    for n in scales {
        let mut a = ThreadAnalyzer::new();
        for t in [1u32, 2, 3] {
            a.feed_thread_info(thread_info(t));
        }
        // Alternate write(T1)/read(T2)/write(T3) on ONE address => maximal pairing.
        for i in 0..n {
            let step = i as u64;
            match i % 3 {
                0 => a.feed_memory_write(step, 1, 0x5000_0000, 4),
                1 => a.feed_memory_read(step, 2, 0x5000_0000, 4),
                _ => a.feed_memory_write(step, 3, 0x5000_0000, 4),
            }
        }
        let t = Instant::now();
        let races = a.detect_race_conditions();
        let sec = t.elapsed().as_secs_f64();
        println!("n={:>7}  races={:>9}  detect={:>9.3}s", n, races.len(), sec);
    }
}
