use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use chrono;

pub const SAVEPOINT_FILE: &str = "brute_savepoint.txt";

/// Structure to hold the current progress for saving/resuming
pub struct SavePoint {
    pub cpu_position: u128,
    pub gpu_position: u128,
    pub cpu_ops_completed: u64,
    pub gpu_ops_completed: u64,
    pub timestamp: u64, // Unix timestamp
}

impl SavePoint {
    pub fn new(cpu_pos: u128, gpu_pos: u128, cpu_ops: u64, gpu_ops: u64) -> Self {
        SavePoint {
            cpu_position: cpu_pos,
            gpu_position: gpu_pos,
            cpu_ops_completed: cpu_ops,
            gpu_ops_completed: gpu_ops,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
    
    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let contents = format!("{}\n{}\n{}\n{}\n{}", 
            self.cpu_position, 
            self.gpu_position,
            self.cpu_ops_completed,
            self.gpu_ops_completed,
            self.timestamp
        );
        fs::write(path, contents)
    }
    
    pub fn load_from_file(path: &str) -> Option<Self> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                let lines: Vec<&str> = contents.lines().collect();
                if lines.len() >= 5 {
                    let cpu_pos = lines[0].parse::<u128>().ok()?;
                    let gpu_pos = lines[1].parse::<u128>().ok()?;
                    let cpu_ops = lines[2].parse::<u64>().ok()?;
                    let gpu_ops = lines[3].parse::<u64>().ok()?;
                    let timestamp = lines[4].parse::<u64>().ok()?;
                    
                    Some(SavePoint {
                        cpu_position: cpu_pos,
                        gpu_position: gpu_pos,
                        cpu_ops_completed: cpu_ops,
                        gpu_ops_completed: gpu_ops,
                        timestamp,
                    })
                } else {
                    None
                }
            },
            Err(_) => None,
        }
    }
}

pub fn start_savepoint_thread(
    counter: Arc<AtomicU64>, 
    gpu_counter: Arc<AtomicU64>,
    cpu_pos: Arc<Mutex<u128>>,
    gpu_pos: Arc<Mutex<u128>>,
    found: Arc<AtomicBool>
) {
    thread::spawn(move || {
        while !found.load(Ordering::Relaxed) {
            // Sleep for 60 seconds
            thread::sleep(Duration::from_secs(60));
            // Create and save a savepoint
            let savepoint = SavePoint::new(
                *cpu_pos.lock().unwrap(),
                *gpu_pos.lock().unwrap(),
                counter.load(Ordering::Relaxed),
                gpu_counter.load(Ordering::Relaxed)
            );
            
            if let Err(e) = savepoint.save_to_file(SAVEPOINT_FILE) {
                println!("Warning: Failed to write savepoint: {}", e);
            } else {
                println!("Savepoint written at {}", 
                    chrono::DateTime::<chrono::Local>::from(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(savepoint.timestamp)
                    ).format("%Y-%m-%d %H:%M:%S"));
            }
        }
    });
}
