// SPDX-License-Identifier: Apache-2.0
//! Bounded serialization shared by device and VMM checkpoint state.

use bincode::enc::write::Writer;
use bincode::error::EncodeError;
use serde::{de::DeserializeOwned, Serialize};
use std::io;

struct LimitedWriter<const LIMIT: usize> {
    bytes: Vec<u8>,
}

impl<const LIMIT: usize> Writer for LimitedWriter<LIMIT> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        if bytes.len() > LIMIT - self.bytes.len() {
            return Err(EncodeError::Other("checkpoint state exceeds size limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

pub fn encode<T: Serialize, const LIMIT: usize>(state: &T) -> io::Result<Vec<u8>> {
    let mut writer = LimitedWriter::<LIMIT> { bytes: Vec::new() };
    // Fixed-width integers keep encoded lengths equal to the serde decoder's
    // byte budget. Varints can fit on disk yet exceed that budget on restore.
    // Bincode's encode configuration does not enforce its configured limit.
    bincode::serde::encode_into_writer(
        state,
        &mut writer,
        bincode::config::standard().with_fixed_int_encoding(),
    )
    .map_err(io::Error::other)?;
    Ok(writer.bytes)
}

pub fn decode<T: DeserializeOwned, const LIMIT: usize>(bytes: &[u8]) -> io::Result<T> {
    if bytes.len() > LIMIT {
        return Err(io::Error::other("checkpoint state exceeds size limit"));
    }
    let (state, consumed) = bincode::serde::decode_from_slice(
        bytes,
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_limit::<LIMIT>(),
    )
    .map_err(io::Error::other)?;
    if consumed != bytes.len() {
        return Err(io::Error::other("trailing checkpoint state bytes"));
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_checkpoint_codec_enforces_the_same_budget_on_both_sides() {
        let state = vec![0u64, 1];
        let payload = encode::<_, 24>(&state).unwrap();
        assert_eq!(decode::<Vec<u64>, 24>(&payload).unwrap(), state);
        assert!(encode::<_, 23>(&state)
            .unwrap_err()
            .to_string()
            .contains("limit"));
        assert!(decode::<Vec<u64>, 23>(&payload)
            .unwrap_err()
            .to_string()
            .contains("limit"));
    }

    #[test]
    fn memory_checkpoint_codec_rejects_truncated_and_trailing_bytes() {
        let mut payload = encode::<_, 64>(&vec![7u64]).unwrap();
        assert!(decode::<Vec<u64>, 64>(&payload[..payload.len() - 1]).is_err());
        payload.push(0);
        assert!(decode::<Vec<u64>, 64>(&payload)
            .unwrap_err()
            .to_string()
            .contains("trailing"));
    }
}
