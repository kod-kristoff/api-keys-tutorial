pub fn encode_lowercase(data: &[u8]) -> String {
    base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, data)
}
