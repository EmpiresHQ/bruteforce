use std::env;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::thread;

use libaes::Cipher;
use md5;
use rayon::prelude::*;
use uuid::Uuid;
use tiny_http::{Server, Response};

/// Derives a key (32 bytes) and IV (16 bytes) from a password and salt,
/// using the OpenSSL EVP_BytesToKey method (with MD5).
fn evp_bytes_to_key(pass: &str, salt: &[u8]) -> ([u8; 32], [u8; 16]) {
    let mut data = Vec::new();
    let mut prev = Vec::new();
    while data.len() < 48 {
        let mut md5_input = Vec::new();
        md5_input.extend_from_slice(&prev);
        md5_input.extend_from_slice(pass.as_bytes());
        md5_input.extend_from_slice(salt);
        let digest = md5::compute(&md5_input);
        prev = digest.0.to_vec();
        data.extend_from_slice(&prev);
    }
    
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    
    key.copy_from_slice(&data[..32]);
    iv.copy_from_slice(&data[32..48]);
    
    (key, iv)
}

/// OpenSSL puts "Salted__" (8 bytes) then an 8-byte salt at the beginning of the file.
fn parse_encrypted_file(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.len() < 16 {
        return None;
    }
    if &data[..8] != b"Salted__" {
        return None;
    }
    Some((&data[8..16], &data[16..]))
}

/// Convert a candidate value (from a 122‑bit space) into a valid UUID‑v4.
/// The UUID‑v4 layout requires that the 13th hexadecimal digit is “4” (the version)
/// and that the 17th hexadecimal digit is one of 8, 9, A, or B (the variant).
fn candidate_to_uuid(random_part: u128) -> Uuid {
    let mut bytes = [0u8; 16];
    // Break the 122 random bits into fields.
    // The fields come from:
    //   • time_low: 32 bits (highest bits)
    //   • time_mid: 16 bits
    //   • time_hi: 12 bits
    //   • clock_seq: 14 bits
    //   • node: 48 bits (lowest bits)
    let time_low = (random_part >> 90) as u32;
    let time_mid = ((random_part >> 74) & 0xFFFF) as u16;
    let time_hi = ((random_part >> 62) & 0x0FFF) as u16;
    let clock_seq = ((random_part >> 48) & 0x3FFF) as u16;
    let node = (random_part & 0xFFFFFFFFFFFF) as u64;

    // Inject fixed bits.
    let time_hi_and_version = (0x4000u16) | time_hi; // set version 4
    let clock_seq_hi_and_reserved = (((clock_seq >> 8) & 0x3F) as u8) | 0x80; // set variant bits to 10
    let clock_seq_low = (clock_seq & 0xFF) as u8;

    // Pack the fields into the 16-byte array (big‑endian layout):
    bytes[0] = (time_low >> 24) as u8;
    bytes[1] = (time_low >> 16) as u8;
    bytes[2] = (time_low >> 8) as u8;
    bytes[3] = time_low as u8;

    bytes[4] = (time_mid >> 8) as u8;
    bytes[5] = time_mid as u8;

    bytes[6] = (time_hi_and_version >> 8) as u8;
    bytes[7] = time_hi_and_version as u8;

    bytes[8] = clock_seq_hi_and_reserved;
    bytes[9] = clock_seq_low;

    bytes[10] = (node >> 40) as u8;
    bytes[11] = (node >> 32) as u8;
    bytes[12] = (node >> 24) as u8;
    bytes[13] = (node >> 16) as u8;
    bytes[14] = (node >> 8) as u8;
    bytes[15] = node as u8;

    Uuid::from_bytes(bytes)
}

/// Convert a UUID into its “random part” (the underlying 122‐bit integer)
/// by removing the fixed bits.
fn uuid_to_candidate(u: &Uuid) -> u128 {
    let bytes = u.as_bytes();
    let time_low = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u128;
    let time_mid = u16::from_be_bytes([bytes[4], bytes[5]]) as u128;
    let time_hi_and_version = u16::from_be_bytes([bytes[6], bytes[7]]) as u128;
    let clock_seq = u16::from_be_bytes([bytes[8], bytes[9]]) as u128;
    let node = ((bytes[10] as u128) << 40)
        | ((bytes[11] as u128) << 32)
        | ((bytes[12] as u128) << 24)
        | ((bytes[13] as u128) << 16)
        | ((bytes[14] as u128) << 8)
        | (bytes[15] as u128);

    let time_hi = time_hi_and_version & 0x0FFF; // remove fixed version nibble
    let clock_seq_val = clock_seq & 0x3FFF; // remove variant bits

    // Reassemble the candidate from its fields:
    (time_low << 90) | (time_mid << 74) | (time_hi << 62) | (clock_seq_val << 48) | node
}

/// Given a passphrase candidate, attempt decryption and check for a "hit."
fn decrypt_and_check(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Option<String> {
    // Create a new AES-256 cipher instance
    let cipher = Cipher::new_256(key);
    
    // Try to decrypt
    let plain_bytes = cipher.cbc_decrypt(iv, ciphertext);
    
    // Define byte patterns to search for
    let flag_pattern = b"flag{";
    let challenge_pattern = b"challenge";
    
    // Check if the decrypted bytes contain the patterns
    if plain_bytes.windows(flag_pattern.len()).any(|window| window == flag_pattern) || 
       plain_bytes.windows(challenge_pattern.len()).any(|window| window == challenge_pattern) {
        
        // Only convert to UTF-8 string if pattern is found
        if let Ok(plain_text) = String::from_utf8(plain_bytes) {
            return Some(plain_text);
        }
    }
    
    None
}

struct BruteforceStats {
    counter: Arc<AtomicU64>,
    start_time: Instant,
    max_iterations: u128,
    found: Arc<AtomicBool>,
    result: Arc<Mutex<Option<(u128, Uuid, String)>>>,
    last_checked: Arc<Mutex<String>>,
}

fn start_web_server(stats: BruteforceStats) {
    thread::spawn(move || {
        let server = Server::http("0.0.0.0:8889").unwrap();
        println!("Web server started at http://localhost:8889");
        
        for request in server.incoming_requests() {
            let current_count = stats.counter.load(Ordering::Relaxed);
            let elapsed = stats.start_time.elapsed();
            let elapsed_secs = elapsed.as_secs_f64();
            let ops_per_sec = if elapsed_secs > 0.0 { 
                (current_count as f64 / elapsed_secs).ceil() as u64 
            } else { 
                0 
            };
            
            let progress_percent = (current_count as f64 / stats.max_iterations as f64 * 100.0) as u64;
            let num_threads = rayon::current_num_threads();
            
            let mut result_info = String::new();
            if stats.found.load(Ordering::Relaxed) {
                if let Some((_, uuid, decrypted)) = &*stats.result.lock().unwrap() {
                    result_info = format!(
                        "<div class='success'>
                            <h2>🎉 Solution Found!</h2>
                            <p><strong>UUID:</strong> {}</p>
                            <pre>{}</pre>
                        </div>",
                        uuid, decrypted
                    );
                }
            }
            
            let current_uuid = stats.last_checked.lock().unwrap().clone();
            
            let html = format!(
                r#"<!DOCTYPE html>
                <html>
                <head>
                    <title>UUID Brute Force Progress</title>
                    <meta http-equiv="refresh" content="2">
                    <style>
                        body {{ font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 20px; line-height: 1.6; }}
                        .container {{ max-width: 800px; margin: 0 auto; }}
                        .card {{ background: #f5f5f5; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                        .progress-bar {{ height: 20px; background-color: #e0e0e0; border-radius: 10px; margin: 10px 0; }}
                        .progress-bar-fill {{ height: 100%; background-color: #4caf50; border-radius: 10px; width: {}%; }}
                        .stat-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }}
                        .stat {{ background: #fff; padding: 15px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
                        .success {{ background-color: #d4edda; border-color: #c3e6cb; color: #155724; padding: 15px; border-radius: 8px; }}
                        pre {{ background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>UUID Brute Force Progress</h1>
                        
                        {}
                        
                        <div class="card">
                            <h2>Progress</h2>
                            <div class="progress-bar">
                                <div class="progress-bar-fill"></div>
                            </div>
                            <p>{} of {} iterations completed ({}%)</p>
                        </div>
                        
                        <div class="card">
                            <h2>Statistics</h2>
                            <div class="stat-grid">
                                <div class="stat">
                                    <h3>Speed</h3>
                                    <p>{} operations/second</p>
                                </div>
                                <div class="stat">
                                    <h3>Elapsed Time</h3>
                                    <p>{:02}:{:02}:{:02}</p>
                                </div>
                                <div class="stat">
                                    <h3>Threads</h3>
                                    <p>{} active threads</p>
                                </div>
                                <div class="stat">
                                    <h3>Last Checked</h3>
                                    <p>{}</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </body>
                </html>"#,
                progress_percent,
                result_info,
                current_count,
                stats.max_iterations,
                progress_percent,
                ops_per_sec,
                (elapsed.as_secs() / 3600), // hours
                (elapsed.as_secs() / 60) % 60, // minutes
                elapsed.as_secs() % 60, // seconds
                num_threads,
                current_uuid
            );
            
            // Create a response with proper Content-Type header
            let response = Response::from_string(html)
                .with_header(tiny_http::Header {
                    field: "Content-Type".parse().unwrap(),
                    value: "text/html; charset=utf-8".parse().unwrap(),
                });
            
            let _ = request.respond(response);
            
            // Stop server if work is done and a bit of time has passed for final view
            if stats.found.load(Ordering::Relaxed) && elapsed.as_secs() > 5 {
                break;
            }
        }
    });
}

fn main() {
    // To maximize optimizations on a Mac M3 Pro, build in release mode with:
    //     cargo rustc --release -- -C target-cpu=native
    let args: Vec<String> = env::args().collect();
    // Optionally, a maximum iteration count can be provided.
    // (For a full brute-force, the search space is 2^122; here we limit the range for demonstration.)
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
    let last_checked = Arc::new(Mutex::new(String::new()));
    let start_time = Instant::now();
    
    // Set up web server stats
    let stats = BruteforceStats {
        counter: counter.clone(),
        start_time,
        max_iterations,
        found: found.clone(),
        result: result_uuid.clone(),
        last_checked: last_checked.clone(),
    };
    
    // Start web server
    start_web_server(stats);

    // Use Rayon's parallel iterator to utilize all cores.
    (start_candidate..start_candidate + max_iterations)
        .into_par_iter()
        .for_each(|cand| {
            // Early exit if another thread found the solution.
            if found.load(Ordering::Relaxed) {
                return;
            }
            
            let candidate_uuid = candidate_to_uuid(cand);
            let pass_candidate = candidate_uuid.to_string();
            
            // Update the last checked UUID (occasionally - not for every UUID to reduce lock contention)
            if cand % 1000 == 0 {
                let mut last = last_checked.lock().unwrap();
                *last = pass_candidate.clone();
            }
            
            // Derive key and IV once per UUID
            let (key, iv) = evp_bytes_to_key(&pass_candidate, salt);
            
            // Update counter for operations per second calculation
            counter.fetch_add(1, Ordering::Relaxed);
            
            if let Some(decrypted) = decrypt_and_check(&key, &iv, ciphertext) {
                let num_threads = rayon::current_num_threads();
                let ops_per_sec = (counter.load(Ordering::Relaxed) as f64 / start_time.elapsed().as_secs_f64()).ceil() as u64;
                
                println!("\nSolution found!");
                println!("Candidate UUID: {}", pass_candidate);
                println!("Speed: {} ops/sec with {} threads", ops_per_sec, num_threads);
                
                found.store(true, Ordering::Relaxed);
                let mut res = result_uuid.lock().unwrap();
                *res = Some((cand, candidate_uuid, decrypted));
            }
        });
    
    if let Some((_, uuid, decrypted)) = &*result_uuid.lock().unwrap() {
        println!("\nSuccess! The passphrase UUID is: {}", uuid);
        println!("Decrypted message:\n{}", decrypted);
        
        // Display final stats
        let total_time = start_time.elapsed();
        let total_ops = counter.load(Ordering::Relaxed);
        let num_threads = rayon::current_num_threads();
        println!("Total time: {:.2} seconds", total_time.as_secs_f64());
        println!("Operations performed: {}", total_ops);
        println!("Average speed: {} ops/sec with {} threads", 
            (total_ops as f64 / total_time.as_secs_f64()).ceil() as u64,
            num_threads);
        
        // Keep the program running briefly to allow viewing final results on web server
        println!("Web server will remain active for 10 more seconds...");
        thread::sleep(Duration::from_secs(10));
    } else {
        println!("\nNo valid passphrase found in the given candidate range.");
    }
}
