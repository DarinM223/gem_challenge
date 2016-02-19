// Globals
//

/// An array of bytes containing all of the possible base64 characters
const BASE64_CHARS: &'static [u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// An array of bytes containing all of the possible hex characters
const HEX_CHARS: &'static [u8] = b"0123456789abcdef";

// Helper functions/types
//

#[derive(Clone, Debug, PartialEq)]
enum HexResult {
    /// The decimal byte translation of the hexadecimal byte character
    Byte(u8),
    /// A byte that should be stripped out like a newline or tab
    Ignore,
    /// An invalid hexadecimal byte like '~'
    Invalid,
}

/// Decodes a hex byte
fn decode_hex(hex: u8) -> HexResult {
    match hex {
        b'A'...b'F' => HexResult::Byte((hex - b'A') + 10),
        b'a'...b'f' => HexResult::Byte((hex - b'a') + 10),
        b'0'...b'9' => HexResult::Byte((hex - b'0')),
        b' ' | b'\r' | b'\n' | b'\t' => HexResult::Ignore,
        _ => HexResult::Invalid,
    }
}

/// Converts a string of hexadecimal characters to a vector of bytes
fn bytes_from_hex_str(hex_str: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex_str.len() / 2);
    let mut modulus = 0;
    let mut buf = 08;

    for byte in hex_str.bytes() {
        match decode_hex(byte) {
            HexResult::Byte(byte) => {
                buf <<= 4;
                buf |= byte;

                modulus += 1;
                if modulus == 2 {
                    modulus = 0;
                    bytes.push(buf);
                }
            }
            HexResult::Ignore => {}
            HexResult::Invalid => panic!("Character is not a hex character"),
        }
    }

    bytes
}

/// Converts a vector of hexadecimal encoded bytes to a string
fn hex_bytes_to_str(hex: &Vec<u8>) -> String {
    let mut bytes = Vec::with_capacity(hex.len() * 2);

    for byte in hex {
        bytes.push(HEX_CHARS[(byte >> 4) as usize]);
        bytes.push(HEX_CHARS[(byte & 0xf) as usize]);
    }

    unsafe { String::from_utf8_unchecked(bytes) }
}

/// Converts a vector of bytes into a base64 encoded string
fn bytes_to_base64(bytes: &Vec<u8>) -> String {
    let padding_len = bytes.len() % 3;
    let mut result = Vec::new();

    let mut in_iter = bytes[..bytes.len() - padding_len].iter().map(|&b| b as u32);
    let mut len = 0;

    while let (Some(i1), Some(i2), Some(i3)) = (in_iter.next(), in_iter.next(), in_iter.next()) {
        if len >= 76 {
            result.push(b'\r');
            result.push(b'\n');
            len = 0;
        }

        let n = i1 << 16 | i2 << 8 | i3;
        let n1 = ((n >> 18) & 63) as usize;
        let n2 = ((n >> 12) & 63) as usize;
        let n3 = ((n >> 6) & 63) as usize;
        let n4 = (n & 63) as usize;

        result.push(BASE64_CHARS[n1]);
        result.push(BASE64_CHARS[n2]);
        result.push(BASE64_CHARS[n3]);
        result.push(BASE64_CHARS[n4]);

        len += 4;
    }

    unsafe { String::from_utf8_unchecked(result) }
}

/// Returns the rank of the string by checking for
/// uppercase letters only for the first letters in strings
/// and only alphabetic letters in words
fn string_rank(s: &str) -> i32 {
    let mut match_rank = 0;

    for word in s.split(' ') {
        for (idx, ch) in word.chars().enumerate() {
            if idx != 0 && ch.is_uppercase() {
                match_rank -= 1;
            } else if !ch.is_alphabetic() && ch != ' ' {
                match_rank -= 1;
            } else {
                match_rank += 1;
            }
        }
    }

    match_rank
}

// Main functions
//

/// Takes in a hex string and returns the base64 of it
pub fn hex_to_base64(hex: &str) -> String {
    let bytes = bytes_from_hex_str(hex);
    bytes_to_base64(&bytes)
}

/// Produces the xor combination of two buffers
pub fn fixed_xor(buf1: &str, buf2: &str) -> String {
    if buf1.len() != buf2.len() {
        panic!("The length of the two buffers have to be the same");
    }

    let mut buf1_iter = bytes_from_hex_str(buf1).into_iter();
    let mut buf2_iter = bytes_from_hex_str(buf2).into_iter();
    let mut result = Vec::with_capacity(buf1.len());

    while let (Some(b1), Some(b2)) = (buf1_iter.next(), buf2_iter.next()) {
        result.push(b1 ^ b2);
    }

    hex_bytes_to_str(&result)
}

/// Returns the character that is xored to the string
/// to decrypt the cipher
pub fn xor_cipher(hex: &str) -> char {
    let bytes = bytes_from_hex_str(hex);
    let mut possible_strings = vec![Vec::new(); 256];

    for byte in bytes {
        for other_byte in 0..255 {
            let xored_byte: u8 = byte ^ other_byte;
            // only add character if it is printable
            if ((xored_byte as i32) - 0x20) < 0x5F {
                possible_strings.get_mut(other_byte as usize).unwrap().push(xored_byte);
            }
        }
    }

    // Compare the strings by rank and get the byte that creates the
    // maximum rank string
    let mut max_byte: u8 = 0;
    let mut max_rank = 0;
    for (idx, bytes) in possible_strings.into_iter().enumerate() {
        let decoded_combination = unsafe { String::from_utf8_unchecked(bytes) };
        let rank = string_rank(&decoded_combination[..]);
        if rank > max_rank {
            max_rank = rank;
            max_byte = idx as u8;
        }
    }

    max_byte as char
}

// Test suite
//

#[test]
fn test_hex_to_byte() {
    assert_eq!(decode_hex(b'~'), HexResult::Invalid);
    assert_eq!(decode_hex(b' '), HexResult::Ignore);
    assert_eq!(decode_hex(b'\t'), HexResult::Ignore);
    assert_eq!(decode_hex(b'\n'), HexResult::Ignore);
    assert_eq!(decode_hex(b'5'), HexResult::Byte(5 as u8));
    assert_eq!(decode_hex(b'F'), HexResult::Byte(15 as u8));
    assert_eq!(decode_hex(b'f'), HexResult::Byte(15 as u8));
}

#[test]
fn test_hex_to_base64() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206\
                 d757368726f6f6d";
    let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(hex_to_base64(input), expected_output.to_owned());
}

#[test]
fn test_fixed_xor() {
    let input1 = "1c0111001f010100061a024b53535009181c";
    let input2 = "686974207468652062756c6c277320657965";
    let expected_output = "746865206b696420646f6e277420706c6179";
    assert_eq!(fixed_xor(input1, input2), expected_output.to_owned());
}

#[test]
fn test_xor_cipher() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    assert_eq!(xor_cipher(input), 'X');
}
