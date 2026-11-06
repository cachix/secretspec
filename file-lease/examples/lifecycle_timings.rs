//! Small, synthetic latency probe. Run on the target OS with:
//! cargo run -p file-lease --example lifecycle_timings

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sample() -> std::io::Result<[f64; 3]> {
    use file_lease::FileLease;
    use std::{io, time::Instant};

    let start = Instant::now();
    let lease = FileLease::new(std::process::id()).with_keeper_executable(std::env::current_exe()?);
    let first = lease.materialize(&[42; 256], None)?;
    let setup = start.elapsed().as_secs_f64() * 1000.0;
    if std::fs::read(&first)? != [42; 256] {
        return Err(io::Error::other("Incorrect synthetic file contents"));
    }

    let start = Instant::now();
    let second = lease.materialize(&[43; 256], None)?;
    let next_file = start.elapsed().as_secs_f64() * 1000.0;

    let start = Instant::now();
    drop(lease);
    let cleanup = start.elapsed().as_secs_f64() * 1000.0;
    if first.exists() || second.exists() {
        return Err(io::Error::other("Synthetic file survived lease cleanup"));
    }
    Ok([setup, next_file, cleanup])
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() -> std::io::Result<()> {
    use std::sync::{Arc, Barrier};

    if let Some(code) = file_lease::maybe_run_keeper() {
        std::process::exit(code);
    }
    println!("mode,sample,setup_ms,next_file_ms,cleanup_ms");
    for index in 0..5 {
        let [setup, next_file, cleanup] = sample()?;
        println!("sequential,{index},{setup:.3},{next_file:.3},{cleanup:.3}");
    }
    let barrier = Arc::new(Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                sample()
            })
        })
        .collect();
    for (index, thread) in threads.into_iter().enumerate() {
        let [setup, next_file, cleanup] = thread
            .join()
            .map_err(|_| std::io::Error::other("Latency probe thread panicked"))??;
        println!("parallel,{index},{setup:.3},{next_file:.3},{cleanup:.3}");
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "File lease timings require Linux or macOS",
    ))
}
