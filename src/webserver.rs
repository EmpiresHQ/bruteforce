use std::sync::atomic::Ordering;
use std::thread;

use rayon;
use tiny_http::{Server, Response};
use chrono;

use crate::utils::{BruteforceStats, format_ops, format_with_spaces};

pub fn start_web_server(stats: BruteforceStats) {
    thread::spawn(move || {
        let server = Server::http("0.0.0.0:8889").unwrap();
        println!("Web server started at http://localhost:8889");
        
        for request in server.incoming_requests() {
            let current_count = stats.counter.load(Ordering::Relaxed);
            let gpu_count = stats.gpu_ops_count.load(Ordering::Relaxed);
            let total_count = current_count + gpu_count;
            
            let elapsed = stats.start_time.elapsed();
            let elapsed_secs = elapsed.as_secs_f64();
            
            // Get references to the rate trackers to avoid moving them
            let cpu_ops_per_sec;
            let gpu_ops_per_sec;
            
            // Clone the rate tracker references to avoid ownership issues
            let cpu_tracker_ref = &stats.cpu_rate_tracker;
            let gpu_tracker_ref = &stats.gpu_rate_tracker;
            
            // Update CPU tracker using the reference
            {
                let mut cpu_tracker = cpu_tracker_ref.lock().unwrap();
                cpu_tracker.update(current_count);
                cpu_ops_per_sec = cpu_tracker.rate_per_second();
            }
            
            // Update GPU tracker using the reference
            {
                let mut gpu_tracker = gpu_tracker_ref.lock().unwrap();
                gpu_tracker.update(gpu_count);
                gpu_ops_per_sec = gpu_tracker.rate_per_second();
            }
            
            let ops_per_sec = cpu_ops_per_sec + gpu_ops_per_sec;
            
            // Use the historical average as a sanity check on the calculated rate
            let historical_ops_per_sec = if elapsed_secs > 0.0 {
                (total_count as f64 / elapsed_secs).ceil() as u64
            } else {
                0
            };
            
            // More sophisticated validation logic
            let validated_ops_per_sec = if elapsed_secs < 3.0 {
                // Use historical for the first few seconds
                historical_ops_per_sec
            } else if ops_per_sec > (historical_ops_per_sec as f64 * 1.5) as u64 {
                // Blend rates if the tracker rate is significantly higher
                ((historical_ops_per_sec as f64 * 0.7) + (ops_per_sec as f64 * 0.3)).ceil() as u64
            } else if ops_per_sec < (historical_ops_per_sec as f64 * 0.5) as u64 && ops_per_sec > 0 {
                // Blend rates if the tracker rate is significantly lower
                ((historical_ops_per_sec as f64 * 0.7) + (ops_per_sec as f64 * 0.3)).ceil() as u64
            } else {
                // Use the tracker rate when it seems reasonable
                ops_per_sec
            };
            
            // Display both current and average rates in the UI
            let formatted_current_ops = format_ops(ops_per_sec);
            let formatted_historical_ops = format_ops(historical_ops_per_sec);
            let formatted_validated_ops = format_ops(validated_ops_per_sec);
            
            // Format counts with spaces for better readability
            let formatted_total = format_with_spaces(total_count);
            let formatted_max = format_with_spaces(stats.max_iterations as u64);
            let formatted_cpu_count = format_with_spaces(current_count);
            let formatted_gpu_count = format_with_spaces(gpu_count);
            
            let progress_percent = (total_count as f64 / stats.max_iterations as f64 * 100.0) as u64;
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
            
            let gpu_status = if stats.gpu_enabled {
                format!(
                    "<div class=\"stat success-bg\"><h3>GPU Status</h3><p>Active - {} operations ({} ops/sec)</p></div>", 
                    formatted_gpu_count, 
                    formatted_current_ops
                )
            } else {
                "<div class=\"stat\"><h3>GPU Status</h3><p>Not available</p></div>".to_string()
            };
            
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
                        .success-bg {{ background-color: #d4edda; color: #155724; }}
                        pre {{ background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>UUID Brute Force Progress</h1>
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
                                    <h3>Total Speed</h3>
                                    <p>{} ops/sec</p>
                                </div>
                                <div class="stat">
                                    <h3>Current Speed</h3>
                                    <p>{} ops/sec</p>
                                    <small>Historical avg: {} ops/sec</small>
                                </div>
                                <div class="stat">
                                    <h3>Elapsed Time</h3>
                                    <p>{:02}:{:02}:{:02}</p>
                                </div>
                                <div class="stat">
                                    <h3>CPU Operations</h3>
                                    <p>{} ({} ops/sec)</p>
                                </div>
                                <div class="stat">
                                    <h3>Last Checked</h3>
                                    <p>{}</p>
                                </div>
                                <div class="stat">
                                    <h3>CPU Threads</h3>
                                    <p>{} active threads</p>
                                </div>
                                {}
                            </div>
                        </div>
                        {}
                    </div>
                </body>
                </html>"#,
                progress_percent,
                formatted_total,
                formatted_max,
                progress_percent,
                formatted_validated_ops,
                formatted_current_ops,
                formatted_historical_ops,
                (elapsed.as_secs() / 3600), // hours
                (elapsed.as_secs() / 60) % 60, // minutes
                elapsed.as_secs() % 60, // seconds
                formatted_cpu_count, formatted_current_ops, // CPU ops count and ops/sec
                current_uuid,
                num_threads,
                gpu_status,
                result_info
            );
            
            let response = Response::from_string(html)
                .with_header(tiny_http::Header {
                    field: "Content-Type".parse().unwrap(),
                    value: "text/html; charset=utf-8".parse().unwrap(),
                });
            let _ = request.respond(response);
            
            if stats.found.load(Ordering::Relaxed) && elapsed.as_secs() > 5 {
                break;
            }
        }
    });
}
