use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/shader.metal");
    
    let out_dir = env::var("OUT_DIR").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    
    if target_os == "macos" {
        // Compile Metal shader
        let shader_path = Path::new("src/shader.metal");
        if shader_path.exists() {
            println!("Compiling Metal shader...");
            let output = Command::new("xcrun")
                .args(&["-sdk", "macosx", "metal", "-c", shader_path.to_str().unwrap(),
                      "-o", &format!("{}/shader.air", out_dir)])
                .output();
            
            match output {
                Ok(output) => {
                    if !output.status.success() {
                        eprintln!("Metal shader compilation failed: {}", 
                            String::from_utf8_lossy(&output.stderr));
                    } else {
                        println!("Metal shader compiled successfully");
                    }
                },
                Err(e) => {
                    eprintln!("Failed to execute Metal compiler: {}", e);
                }
            }
        } else {
            eprintln!("Metal shader file not found at: {:?}", shader_path);
        }
    } else {
        println!("Skipping Metal shader compilation on non-macOS platform");
    }
}
