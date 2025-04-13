use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use uuid::Uuid;

/// A structure to track operation rates with a sliding window approach
pub struct RateTracker {
    pub timestamps: Vec<Instant>,
    pub counts: Vec<u64>,
    pub window_size: usize,
    pub last_total: u64,
}

impl RateTracker {
    pub fn new(window_size: usize) -> Self {
        RateTracker {
            timestamps: Vec::with_capacity(window_size),
            counts: Vec::with_capacity(window_size),
            window_size,
            last_total: 0,
        }
    }
    
    pub fn update(&mut self, current_total: u64) {
        let now = Instant::now();
        
        // Only record if the count has changed
        if current_total > self.last_total {
            self.timestamps.push(now);
            self.counts.push(current_total);
            self.last_total = current_total;
            // Maintain window size
            if self.timestamps.len() > self.window_size {
                self.timestamps.remove(0);
                self.counts.remove(0);
            }
        }
    }
    
    pub fn rate_per_second(&self) -> u64 {
        if self.timestamps.len() < 2 {
            return 0;
        }
        
        // Use a weighted average of different time intervals for better stability
        let mut rates = Vec::new();
        let mut weights = Vec::new();
        
        // Calculate rates for different interval sizes
        for window_size in 2..=self.timestamps.len().min(5) {
            let idx = self.timestamps.len() - window_size;
            let time_diff = self.timestamps[self.timestamps.len() - 1]
                .duration_since(self.timestamps[idx])
                .as_secs_f64();
            
            if time_diff >= 0.1 { // Only use intervals of at least 100ms
                let count_diff = self.counts[self.timestamps.len() - 1] - self.counts[idx];
                let rate = (count_diff as f64 / time_diff) as u64;
                rates.push(rate);
                // Give more weight to larger windows as they're more stable
                weights.push(window_size as f64);
            }
        }
        
        if rates.is_empty() {
            // Fallback to simple first/last calculation
            let time_diff = self.timestamps[self.timestamps.len() - 1]
                .duration_since(self.timestamps[0])
                .as_secs_f64();
            
            if time_diff >= 0.1 {
                let count_diff = self.counts[self.timestamps.len() - 1] - self.counts[0];
                return (count_diff as f64 / time_diff).ceil() as u64;
            }
            return 0;
        }
        
        // Calculate weighted average
        let total_weight: f64 = weights.iter().sum();
        let weighted_sum: f64 = rates.iter().zip(weights.iter())
            .map(|(rate, weight)| *rate as f64 * weight)
            .sum();
        
        (weighted_sum / total_weight).ceil() as u64
    }
}

// Helper function to format large numbers in K/M format
pub fn format_ops(ops: u64) -> String {
    if ops >= 1_000_000 {
        format!("{:.2}M", ops as f64 / 1_000_000.0)
    } else if ops >= 1_000 {
        format!("{:.2}K", ops as f64 / 1_000.0)
    } else {
        ops.to_string()
    }
}

// Format large numbers with spaces for better readability
pub fn format_with_spaces(num: u64) -> String {
    let num_str = num.to_string();
    let mut result = String::new();
    let len = num_str.len();
    
    for (i, c) in num_str.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(' ');
        }
        result.push(c);
    }
    
    result
}

pub struct BruteforceStats {
    pub counter: Arc<AtomicU64>,
    pub start_time: Instant,
    pub max_iterations: u128,
    pub found: Arc<AtomicBool>,
    pub result: Arc<Mutex<Option<(u128, Uuid, String)>>>,
    pub last_checked: Arc<Mutex<String>>,
    pub gpu_ops_count: Arc<AtomicU64>,
    pub gpu_enabled: bool,
    pub cpu_rate_tracker: Arc<Mutex<RateTracker>>,
    pub gpu_rate_tracker: Arc<Mutex<RateTracker>>,
}
