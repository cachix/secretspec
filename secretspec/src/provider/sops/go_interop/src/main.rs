use go_interop::SopsDecryptor;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Decrypt a file
    match SopsDecryptor::decrypt_file("secrets.yaml", "yaml") {
        Ok(cleartext) => {
            println!("Decrypted content: {}", String::from_utf8_lossy(&cleartext));
        }
        Err(e) => eprintln!("Failed to decrypt file: {}", e),
    }

    // Decrypt data from memory
    let encrypted_data = fs::read("secrets.json")?;

    match SopsDecryptor::decrypt_data(&encrypted_data, "json") {
        Ok(cleartext) => {
            println!("Decrypted JSON: {}", String::from_utf8_lossy(&cleartext));
        }
        Err(e) => eprintln!("Failed to decrypt data: {}", e),
    }

    Ok(())
}
