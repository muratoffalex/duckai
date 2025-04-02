use crate::Result;
use crate::error::Error::HashError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn get_hex(s: &str) -> isize {
    let t = if let Some(i) = s.chars().position(|c| c == '(') {
        &s[i + 3..s.len() - 1]
    } else {
        s
    };
    isize::from_str_radix(t, 16).unwrap()
}

fn compute_sha256_base64(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    BASE64_STANDARD.encode(hash)
}

pub fn gen_request_hash(hash: &str) -> Result<String> {
    let decoded_bytes = BASE64_STANDARD
        .decode(hash.as_bytes())
        .expect("invalid base64");
    let decoded_str = String::from_utf8(decoded_bytes).expect("invalid utf-8");

    let string_array: Vec<&str> = Regex::new(r"=\[([^\]]*)\]")
        .unwrap()
        .captures(&decoded_str)
        .and_then(|cap| cap.get(1))
        .ok_or_else(|| HashError("string array not found"))?
        .as_str()
        .split(',')
        .map(|s| s.trim_matches('\''))
        .collect();

    let offset: isize = Regex::new(r"0x([[:alnum:]]+);let")
        .unwrap()
        .captures(&decoded_str)
        .and_then(|cap| cap.get(1))
        .and_then(|s| isize::from_str_radix(s.as_str(), 16).ok())
        .ok_or_else(|| HashError("offset not found"))?;
    // dbg!(&decoded_str);

    let mut shift_offset = None;

    if shift_offset.is_none() {
        let user_agent_pat =
            Regex::new(r"'client_hashes':\[navigator\[[^(]*\(0x([[:alnum:]]+)\)\]")
                .unwrap()
                .captures(&decoded_str)
                .and_then(|cap| cap.get(1))
                .map(|s| s.as_str());
        // dbg!(user_agent_pat);
        if let Some(pat) = user_agent_pat {
            let index = get_hex(pat);
            let origin_index =
                string_array.iter().position(|&s| s == "userAgent").unwrap() as isize;
            shift_offset = Some(origin_index - (index - offset));
        }
    }

    if shift_offset.is_none() {
        let div_pat = Regex::new(r"0x([[:alnum:]])\)\);return\s")
            .unwrap()
            .captures(&decoded_str)
            .and_then(|cap| cap.get(1))
            .map(|s| s.as_str());
        // dbg!(div_pat);
        if let Some(pat) = div_pat {
            let index = get_hex(pat);
            let origin_index = string_array.iter().position(|&s| s == "div").unwrap() as isize;
            shift_offset = Some(origin_index - (index - offset));
        }
    }

    let shift_offset = shift_offset.ok_or_else(|| HashError("shift offset not found"))?;
    // dbg!(shift_offset);

    let mut server_hashes = vec![None, None];

    let server_hash_pats = Regex::new(r"'server_hashes':\[([^,]+),([^]]+)\]")
        .unwrap()
        .captures(&decoded_str)
        .and_then(|cap| {
            let a = cap.get(1).map(|s| s.as_str());
            let b = cap.get(2).map(|s| s.as_str());
            a.zip(b).map(|(a, b)| vec![a, b])
        })
        .ok_or_else(|| HashError("server hash pats not found"))?;
    // dbg!(&server_hash_pats);

    for (i, pat) in server_hash_pats.iter().enumerate() {
        if pat.starts_with('\'') {
            server_hashes[i] = Some(pat.trim_matches('\''));
        } else {
            let index = get_hex(pat);
            let origin_index = (index - offset + shift_offset + string_array.len() as isize)
                % string_array.len() as isize;
            server_hashes[i] = Some(string_array[origin_index as usize]);
        }
    }
    // dbg!(&server_hashes);

    let innerhtml_pat = Regex::new(r"=([^,;]+),String")
        .unwrap()
        .captures(&decoded_str)
        .and_then(|cap| cap.get(1))
        .map(|s| s.as_str())
        .ok_or_else(|| HashError("inner html pat not found"))?;

    let innerhtml = if innerhtml_pat.starts_with('\'') {
        innerhtml_pat.trim_matches('\'')
    } else {
        let index = get_hex(innerhtml_pat);
        let origin_index = (index - offset + shift_offset + string_array.len() as isize)
            % (string_array.len() as isize);
        string_array[origin_index as usize]
    };
    // dbg!(innerhtml);

    let inner_html_data: HashMap<&str, i32> = HashMap::from([
        ("<div><div></div><div></div", 99),
        ("<p><div></p><p></div", 128),
        ("<br><div></br><br></div", 92),
        ("<li><div></li><li></div", 87),
    ]);

    let inner_html_len = inner_html_data
        .get(innerhtml)
        .ok_or_else(|| HashError("unknown inner html pattern"))?;

    let extracted_number: i32 = Regex::new(r"String\(0x([[:alnum:]]+)\+")
        .unwrap()
        .captures(&decoded_str)
        .and_then(|cap| cap.get(1))
        .and_then(|s| i32::from_str_radix(s.as_str(), 16).ok())
        .ok_or_else(|| HashError("extracted number not found"))?;
    // dbg!(extracted_number);

    let user_agent_hash = compute_sha256_base64(crate::client::USER_AGENT);
    let number_hash = compute_sha256_base64(&(extracted_number + inner_html_len).to_string());

    let result_json = serde_json::json!({
        "server_hashes": server_hashes,
        "client_hashes": [user_agent_hash, number_hash],
        "signals": {}
    });
    Ok(BASE64_STANDARD.encode(result_json.to_string()))
}
