use crate::Claims; // Import the Claims struct from lib.rs
use std::error::Error;
use base64::{engine::general_purpose, Engine};

fn decode_base64(input: &str) -> Result<String, Box<dyn Error>> {
    let decoded_bytes = general_purpose::URL_SAFE_NO_PAD.decode(input)?;
    let decoded_str = String::from_utf8(decoded_bytes)?;
    Ok(decoded_str)
}

pub fn decode_jwt(token: &str) -> Result<Claims, Box<dyn Error>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".into());
    }
    // Decode payload
    let payload_json = decode_base64(parts[1])?;
    let claims = serde_json::from_str::<Claims>(&payload_json).expect(&format!("Failed to parse claims: {}", payload_json));

    Ok(claims)
}