mod savepoint;
mod webserver;
mod gpu_processing;
mod cpu_processing;
mod utils;

use std::env;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::thread;

use uuid::Uuid;
use rayon::prelude::*;

use savepoint::{SavePoint, SAVEPOINT_FILE};
use webserver::start_web_server;
use gpu_processing::{start_gpu_thread, GpuMessage, GpuResult};
use cpu_processing::{candidate_to_uuid, uuid_to_candidate, decrypt_and_check, evp_bytes_to_key};
use utils::{BruteforceStats, RateTracker};

fn main() {
    // To maximize optimizations on a Mac M3 Pro, build in release mode with:
    //     cargo rustc --release -- -C target-cpu=native
    
    let args: Vec<String> = env::args().collect();
    // Optionally, a maximum iteration count can be provided.
    let max_iterations: u128 = if args.len() > 1 {
        args[1].parse().expect("Invalid iteration count")
    } else {
        1_000_000_000_000_000 // default; adjust as needed
    };

    // The challenge tells us that the first UUID was:
    let first_uuid_str = "15041508-fd38-4eda-bc1d-7b74e4738cd9";
    let first_uuid = Uuid::parse_str(first_uuid_str).expect("Invalid UUID format");
    // We assume that the secret (the 2nd UUID) is "near" the first one in the underlying 122‑bit candidate space.
    let start_candidate = uuid_to_candidate(&first_uuid) + 1;

    // Load the encrypted file.
    let enc_data = fs::read("impossible-challenge.txt.enc").expect("Failed to read encrypted file");
    let (salt, ciphertext) =
        parse_encrypted_file(&enc_data).expect("Invalid encrypted file format");

    println!(
        "Starting brute-force search from candidate derived from first UUID: {}",
        first_uuid_str
    );
    println!("Trying up to {} candidates...", max_iterations);
    println!("Web monitoring available at http://localhost:8889");
    let found = Arc::new(AtomicBool::new(false));
    let result_uuid = Arc::new(Mutex::new(None));
    let counter = Arc::new(AtomicU64::new(0));
    let gpu_ops_count = Arc::new(AtomicU64::new(0));
    let last_checked = Arc::new(Mutex::new(String::new()));
    let start_time = Instant::now();
    let cpu_position = Arc::new(Mutex::new(0u128));
    let gpu_position = Arc::new(Mutex::new(0u128));
    let cpu_rate_tracker = Arc::new(Mutex::new(RateTracker::new(10))); // 10-point sliding window
    let gpu_rate_tracker = Arc::new(Mutex::new(RateTracker::new(10)));

    // Initialize GPU communication first
    let gpu_channels = start_gpu_thread(found.clone());
    let gpu_enabled = gpu_channels.is_some();

    // Now check for existing savepoint
    let (cpu_start, gpu_start) = if let Some(savepoint) = SavePoint::load_from_file(SAVEPOINT_FILE) {
        println!("Resuming from savepoint created at {}", 
            chrono::DateTime::<chrono::Local>::from(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(savepoint.timestamp)
            ).format("%Y-%m-%d %H:%M:%S"));
        // Set counters from savepoint
        counter.store(savepoint.cpu_ops_completed, Ordering::Relaxed);
        gpu_ops_count.store(savepoint.gpu_ops_completed, Ordering::Relaxed);
        *cpu_position.lock().unwrap() = savepoint.cpu_position;
        *gpu_position.lock().unwrap() = savepoint.gpu_position;
        (savepoint.cpu_position, savepoint.gpu_position)
    } else {
        // No savepoint, start fresh
        let cpu_start = if gpu_enabled {
            start_candidate + 1_000_000_000 // Start CPU search far ahead to avoid duplicating GPU work
        } else {
            start_candidate
        };
        
        *cpu_position.lock().unwrap() = cpu_start;
        *gpu_position.lock().unwrap() = start_candidate;

        (cpu_start, start_candidate)
    };
    
    // Start savepoint writer thread
    savepoint::start_savepoint_thread(
        counter.clone(), 
        gpu_ops_count.clone(),
        cpu_position.clone(),
        gpu_position.clone(),
        found.clone()
    );
    
    // Set up web server stats
    let stats = BruteforceStats {
        counter: counter.clone(),
        start_time,
        max_iterations,
        found: found.clone(),
        result: result_uuid.clone(),
        last_checked: last_checked.clone(),
        gpu_ops_count: gpu_ops_count.clone(),
        gpu_enabled,
        cpu_rate_tracker: cpu_rate_tracker.clone(), // Clone the Arc
        gpu_rate_tracker: gpu_rate_tracker.clone(), // Clone the Arc
    };
    
    // Start web server
    start_web_server(stats);

    // Modified GPU processing
    if let Some((gpu_sender, gpu_receiver)) = gpu_channels {
        let gpu_counter = gpu_ops_count.clone();
        let found_clone = found.clone();
        let result_uuid_clone = result_uuid.clone();
        let gpu_pos = gpu_position.clone();
        
        // Clone the salt and ciphertext before moving into thread
        let salt_clone = salt.clone();
        let ciphertext_clone = ciphertext.clone();
        
        // GPU monitor thread
        thread::spawn(move || {
            let batch_size = 1024 * 128; // Process 128K candidates at a time
            let mut current_candidate = gpu_start;
            // Update the shared GPU position
            *gpu_pos.lock().unwrap() = current_candidate;
            // Send first batch to GPU
            let _ = gpu_sender.send(GpuMessage::ProcessBatch { 
                start_candidate: current_candidate,
                batch_size,
                salt: salt_clone.clone(),
                ciphertext: ciphertext_clone.clone(),
            });
            // Monitor GPU results
            while !found_clone.load(Ordering::Relaxed) &&  
                  (current_candidate - start_candidate) < max_iterations {
                match gpu_receiver.recv() {
                    Ok(GpuResult::BatchProcessed(count)) => {
                        gpu_counter.fetch_add(count, Ordering::Relaxed);
                        current_candidate += batch_size as u128;
                        // Update the shared GPU position
                        *gpu_pos.lock().unwrap() = current_candidate;
                        // Send next batch
                        let _ = gpu_sender.send(GpuMessage::ProcessBatch {
                            start_candidate: current_candidate,
                            batch_size,
                            salt: salt_clone.clone(),
                            ciphertext: ciphertext_clone.clone(),
                        });
                    },
                    Ok(GpuResult::Found(cand, uuid, decrypted)) => {
                        found_clone.store(true, Ordering::Relaxed);
                        let mut res = result_uuid_clone.lock().unwrap();
                        *res = Some((cand, uuid, decrypted));
                        break;
                    },
                    Err(_) => {
                        println!("GPU thread communication error");
                        break;
                    }
                }
            }
            // Shutdown GPU thread
            let _ = gpu_sender.send(GpuMessage::Shutdown);
        });
    }

    // CPU processing with Rayon
    cpu_processing::process_cpu_range(
        cpu_start,
        start_candidate + max_iterations,
        &salt,
        &ciphertext,
        counter.clone(),
        cpu_position.clone(),
        last_checked.clone(),
        found.clone(),
        result_uuid.clone(),
        start_time
    );
    
    if let Some((_, uuid, decrypted)) = &*result_uuid.lock().unwrap() {
        println!("\nSuccess! The passphrase UUID is: {}", uuid);
        println!("Decrypted message:\n{}", decrypted);
        
        let total_time = start_time.elapsed();
        let total_ops = counter.load(Ordering::Relaxed) + gpu_ops_count.load(Ordering::Relaxed);
        let num_threads = rayon::current_num_threads();
        
        // Use the rate tracker for final speed calculation to be consistent with the UI
        let cpu_rate = cpu_rate_tracker.lock().unwrap().rate_per_second();
        let gpu_rate = gpu_rate_tracker.lock().unwrap().rate_per_second();
        let current_rate = cpu_rate + gpu_rate;
        
        // Calculate historical average
        let historical_avg = if total_time.as_secs_f64() > 0.0 {
            (total_ops as f64 / total_time.as_secs_f64()).ceil() as u64
        } else {
            0
        };
        
        println!("Total time: {:.2} seconds", total_time.as_secs_f64());
        println!("Operations performed: {}", total_ops);
        println!("Current speed: {} ops/sec (CPU: {}, GPU: {})", 
            utils::format_ops(current_rate),
            utils::format_ops(cpu_rate),
            utils::format_ops(gpu_rate));
        println!("Average speed: {} ops/sec with {} threads", 
            utils::format_ops(historical_avg),
            num_threads);
        
        println!("Web server will remain active for 10 more seconds...");
        thread::sleep(Duration::from_secs(10));
    } else {
        println!("\nNo valid passphrase found in the given candidate range.");
    }
}

/// OpenSSL puts "Salted__" (8 bytes) then an 8-byte salt at the beginning of the file.
fn parse_encrypted_file(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if data.len() < 16 {
        return None;
    }
    if &data[..8] != b"Salted__" {
        return None;
    }
    Some((data[8..16].to_vec(), data[16..].to_vec()))
}
