use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::sync::{Arc, Mutex};

use uuid::Uuid;
use metal::{Device, MTLResourceOptions};
use objc::rc::autoreleasepool;

use crate::cpu_processing::{candidate_to_uuid, evp_bytes_to_key, decrypt_and_check};

pub enum GpuMessage {
    ProcessBatch {
        start_candidate: u128,
        batch_size: usize,
        salt: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    Shutdown,
}

pub enum GpuResult {
    BatchProcessed(u64),
    Found(u128, Uuid, String),
}

pub fn start_gpu_thread(found: Arc<AtomicBool>) -> Option<(mpsc::Sender<GpuMessage>, mpsc::Receiver<GpuResult>)> {
    // Check if Metal is available without keeping the device reference
    let has_gpu = autoreleasepool(|| {
        if let Some(device) = Device::system_default() {
            if device.is_low_power() {
                println!("No discrete GPU detected. Falling back to CPU-only mode.");
                false
            } else {
                println!("Using Metal GPU acceleration: {}", device.name());
                true
            }
        } else {
            println!("No Metal device found. Falling back to CPU-only mode.");
            false
        }
    });
    
    if !has_gpu {
        return None;
    }
    
    let (tx_to_gpu, rx_in_gpu) = mpsc::channel();
    let (tx_from_gpu, rx_from_gpu) = mpsc::channel();
    
    // Launch GPU thread - Metal objects stay in this thread
    thread::spawn(move || {
        // Initialize Metal directly in the GPU thread
        autoreleasepool(|| {
            // Get a fresh reference to the Metal device in this thread
            let metal_device = match Device::system_default() {
                Some(device) => device,
                None => {
                    println!("Failed to get Metal device in GPU thread");
                    return;
                }
            };
            
            // Set up command queue
            let command_queue = metal_device.new_command_queue();
            
            // Compile the shader from source
            let shader_source = include_str!("shader.metal");
            println!("Compiling Metal shader from source...");
            
            let options = metal::CompileOptions::new();
            let library = match metal_device.new_library_with_source(shader_source, &options) {
                Ok(lib) => {
                    println!("Metal shader compiled successfully");
                    lib
                },
                Err(e) => {
                    println!("Error compiling Metal shader: {:?}", e);
                    return;
                }
            };
            
            // Get compute functions
            let evp_function = match library.get_function("evpBytesToKey", None) {
                Ok(func) => func,
                Err(e) => {
                    println!("Error getting evpBytesToKey function: {:?}", e);
                    return;
                }
            };
            
            let decrypt_function = match library.get_function("decryptAndCheck", None) {
                Ok(func) => func,
                Err(e) => {
                    println!("Error getting decryptAndCheck function: {:?}", e);
                    return;
                }
            };
            
            // Create compute pipelines
            let evp_pipeline = match metal_device.new_compute_pipeline_state_with_function(&evp_function) {
                Ok(state) => state,
                Err(e) => {
                    println!("Error creating evp pipeline: {:?}", e);
                    return;
                }
            };
            
            let decrypt_pipeline = match metal_device.new_compute_pipeline_state_with_function(&decrypt_function) {
                Ok(state) => state,
                Err(e) => {
                    println!("Error creating decrypt pipeline: {:?}", e);
                    return;
                }
            };
            
            println!("Metal pipelines initialized successfully");
            
            // Prepare buffers
            let buffer_size = 1024 * 128; // Prepare for max batch size
            
            // Create buffers
            let buffer_keys = metal_device.new_buffer(
                (buffer_size * 32) as u64, // 32 bytes per key
                MTLResourceOptions::StorageModeShared);
            let buffer_ivs = metal_device.new_buffer(
                (buffer_size * 16) as u64, // 16 bytes per IV
                MTLResourceOptions::StorageModeShared);
            let buffer_results = metal_device.new_buffer(
                (buffer_size * 4) as u64, // 4 bytes per result
                MTLResourceOptions::StorageModeShared);
            let buffer_candidates = metal_device.new_buffer(
                (buffer_size * 16) as u64, // 16 bytes per UUID
                MTLResourceOptions::StorageModeShared);
            
            println!("Metal GPU thread ready to process batches");
            
            // GPU processing loop
            while let Ok(message) = rx_in_gpu.recv() {
                match message {
                    GpuMessage::ProcessBatch { start_candidate, batch_size, salt, ciphertext } => {
                        if found.load(Ordering::Relaxed) {
                            break;
                        }
                        
                        // Create salt and ciphertext buffers
                        let buffer_salt = metal_device.new_buffer_with_data(
                            salt.as_ptr() as *const _, 
                            salt.len() as u64,
                            MTLResourceOptions::StorageModeShared);
                        
                        let buffer_ciphertext = metal_device.new_buffer_with_data(
                            ciphertext.as_ptr() as *const _,
                            ciphertext.len() as u64,
                            MTLResourceOptions::StorageModeShared);
                        
                        // Clear results buffer
                        let results_ptr = buffer_results.contents() as *mut u32;
                        unsafe {
                            std::ptr::write_bytes(results_ptr, 0, batch_size);
                        }
                        
                        // Fill candidates buffer - wrapped in a scope to control lifetime
                        {
                            let candidates_ptr = buffer_candidates.contents() as *mut u8;
                            let candidates_slice = unsafe { std::slice::from_raw_parts_mut(candidates_ptr, batch_size * 16) };
                            
                            for i in 0..batch_size {
                                let candidate = start_candidate + i as u128;
                                let uuid = candidate_to_uuid(candidate);
                                let uuid_bytes = uuid.as_bytes();
                                candidates_slice[i*16..(i+1)*16].copy_from_slice(uuid_bytes);
                            }
                        }
                        
                        // Compute operations in separate scope
                        {
                            let command_buffer = command_queue.new_command_buffer();
                            let compute_encoder = command_buffer.new_compute_command_encoder();
                            
                            // First pass: key derivation
                            compute_encoder.set_compute_pipeline_state(&evp_pipeline);
                            compute_encoder.set_buffer(0, Some(&buffer_candidates), 0);
                            compute_encoder.set_buffer(1, Some(&buffer_keys), 0);
                            compute_encoder.set_buffer(2, Some(&buffer_ivs), 0);
                            compute_encoder.set_buffer(3, Some(&buffer_salt), 0);
                            
                            let threads_per_threadgroup = evp_pipeline.max_total_threads_per_threadgroup() as usize;
                            let threadgroup_count = (batch_size + threads_per_threadgroup - 1) / threads_per_threadgroup;
                            compute_encoder.dispatch_thread_groups(
                                metal::MTLSize::new(threadgroup_count as u64, 1, 1),
                                metal::MTLSize::new(threads_per_threadgroup as u64, 1, 1)
                            );
                            
                            // Second pass: decryption and checking
                            compute_encoder.set_compute_pipeline_state(&decrypt_pipeline);
                            compute_encoder.set_buffer(0, Some(&buffer_keys), 0);
                            compute_encoder.set_buffer(1, Some(&buffer_ivs), 0);
                            compute_encoder.set_buffer(2, Some(&buffer_ciphertext), 0);
                            compute_encoder.set_buffer(3, Some(&buffer_results), 0);
                            compute_encoder.set_buffer(4, Some(&buffer_candidates), 0);
                            
                            // Set ciphertext length as a constant
                            let length = ciphertext.len() as u32;
                            let length_buffer = metal_device.new_buffer_with_data(
                                &length as *const u32 as *const _,
                                std::mem::size_of::<u32>() as u64,
                                MTLResourceOptions::StorageModeShared);
                            compute_encoder.set_buffer(5, Some(&length_buffer), 0);
                            
                            let threads_per_threadgroup = decrypt_pipeline.max_total_threads_per_threadgroup() as usize;
                            let threadgroup_count = (batch_size + threads_per_threadgroup - 1) / threads_per_threadgroup;
                            compute_encoder.dispatch_thread_groups(
                                metal::MTLSize::new(threadgroup_count as u64, 1, 1),
                                metal::MTLSize::new(threads_per_threadgroup as u64, 1, 1)
                            );
                            
                            compute_encoder.end_encoding();
                            command_buffer.commit();
                            command_buffer.wait_until_completed();
                        }
                        
                        // Check results for matches
                        let mut found_match = false;
                        {
                            let results_ptr = buffer_results.contents() as *const u32;
                            let results_slice = unsafe { std::slice::from_raw_parts(results_ptr, batch_size) };
                            
                            for i in 0..batch_size {
                                if results_slice[i] == 1 {
                                    // Found a match, verify on CPU to get the decrypted text
                                    let candidate = start_candidate + i as u128;
                                    let candidate_uuid = candidate_to_uuid(candidate);
                                    let pass_candidate = candidate_uuid.to_string();
                                    let (key, iv) = evp_bytes_to_key(&pass_candidate, &salt);
                                    if let Some(decrypted) = decrypt_and_check(&key, &iv, &ciphertext) {
                                        found.store(true, Ordering::Relaxed);
                                        found_match = true;
                                        println!("GPU found a match!");
                                        let _ = tx_from_gpu.send(GpuResult::Found(candidate, candidate_uuid, decrypted));
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if !found_match {
                            // Report progress
                            let _ = tx_from_gpu.send(GpuResult::BatchProcessed(batch_size as u64));
                        }
                    },
                    GpuMessage::Shutdown => break,
                }
            }
            
            println!("GPU thread shutting down");
        });
    });
    
    Some((tx_to_gpu, rx_from_gpu))
}
