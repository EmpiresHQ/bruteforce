use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use uuid::Uuid;
use libaes::Cipher;
use md5;
use rayon::prelude::*;

/// Convert a candidate value (from a 122‑bit space) into a valid UUID‑v4.
pub fn candidate_to_uuid(random_part: u128) -> Uuid {
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

/// Convert a UUID into its "random part" (the underlying 122‐bit integer)
pub fn uuid_to_candidate(u: &Uuid) -> u128 {
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

/// Derives a key (32 bytes) and IV (16 bytes) from a password and salt
pub fn evp_bytes_to_key(pass: &str, salt: &[u8]) -> ([u8; 32], [u8; 16]) {
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

/// Given a passphrase candidate, attempt decryption and check for a "hit."
pub fn decrypt_and_check(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Option<String> {
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

/// CPU processing function using Rayon
pub fn process_cpu_range(
    start: u128,
    end: u128,
    salt: &[u8],
    ciphertext: &[u8],
    counter: Arc<AtomicU64>,
    cpu_position: Arc<Mutex<u128>>,
    last_checked: Arc<Mutex<String>>,
    found: Arc<AtomicBool>,
    result_uuid: Arc<Mutex<Option<(u128, Uuid, String)>>>,
    start_time: Instant
) {
    (start..end)
        .into_par_iter()
        .for_each(|cand| {
            if found.load(Ordering::Relaxed) {
                return;
            }
            
            // Update the CPU position occasionally
            if cand % 10000 == 0 {
                let mut pos = cpu_position.lock().unwrap();
                *pos = cand;
            }
            
            let candidate_uuid = candidate_to_uuid(cand);
            let pass_candidate = candidate_uuid.to_string();
            
            if cand % 1000 == 0 {
                let mut last = last_checked.lock().unwrap();
                *last = pass_candidate.clone();
            }
            
            // Increment the counter BEFORE performing the expensive operations
            // This ensures we count exactly one operation per iteration
            counter.fetch_add(1, Ordering::Relaxed);
            
            let (key, iv) = evp_bytes_to_key(&pass_candidate, salt);
            
            if let Some(decrypted) = decrypt_and_check(&key, &iv, ciphertext) {
                let num_threads = rayon::current_num_threads();
                // Use the counter value directly for ops calculation
                let total_ops = counter.load(Ordering::Relaxed);
                let ops_per_sec = (total_ops as f64 / start_time.elapsed().as_secs_f64()).ceil() as u64;
                
                println!("\nSolution found!");
                println!("Candidate UUID: {}", pass_candidate);
                println!("Speed: {} ops/sec with {} threads", ops_per_sec, num_threads);
                
                found.store(true, Ordering::Relaxed);
                let mut res = result_uuid.lock().unwrap();
                *res = Some((cand, candidate_uuid, decrypted));
            }
        });
}
