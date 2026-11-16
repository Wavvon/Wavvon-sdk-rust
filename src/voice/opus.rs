//! The one thing the SDK checks about an Opus packet: that it is exactly
//! 20 ms. The desktop decoder's output buffer holds 20 ms, so a 40 or 60 ms
//! packet fails to decode on every desktop listener (sdk-voice.md section 3).

/// Duration of a packet in microseconds, from its TOC byte (RFC 6716 3.1).
pub fn duration_us(packet: &[u8]) -> Result<u32, String> {
    let toc = *packet.first().ok_or("empty packet")?;
    let config = (toc >> 3) as usize;
    let frame_us = match config {
        0..=11 => [10_000, 20_000, 40_000, 60_000][config % 4],
        12..=15 => [10_000, 20_000][config % 2],
        _ => [2_500, 5_000, 10_000, 20_000][config % 4],
    };
    let frames = match toc & 3 {
        0 => 1,
        1 | 2 => 2,
        _ => u32::from(packet.get(1).ok_or("code-3 packet without a frame count")? & 0x3f),
    };
    if frames == 0 {
        return Err("packet declares zero frames".into());
    }
    Ok(frame_us * frames)
}

pub fn check_20ms(packet: &[u8]) -> Result<(), String> {
    match duration_us(packet)? {
        20_000 => Ok(()),
        us => Err(format!("{} ms", f64::from(us) / 1000.0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toc_durations() {
        assert_eq!(duration_us(&[0x08]), Ok(20_000)); // SILK NB 20 ms
        assert_eq!(duration_us(&[0xF8]), Ok(20_000)); // CELT FB 20 ms
        assert_eq!(duration_us(&[0xF0]), Ok(10_000));
        assert_eq!(duration_us(&[0xF9]), Ok(40_000)); // two frames
        assert_eq!(duration_us(&[0x1B, 3]), Ok(180_000)); // 60 ms x 3
        assert_eq!(duration_us(&[0x78]), Ok(20_000)); // hybrid FB 20 ms
    }

    #[test]
    fn only_20_ms_passes() {
        assert!(check_20ms(&[0xF8, 1, 2]).is_ok());
        assert!(check_20ms(&[0xF0]).is_err());
        assert!(check_20ms(&[0xFB, 2]).is_err()); // code 3, two 20 ms frames
        assert!(check_20ms(&[]).is_err());
        assert!(check_20ms(&[0xFB]).is_err());
        assert!(check_20ms(&[0xFB, 0]).is_err());
    }
}
