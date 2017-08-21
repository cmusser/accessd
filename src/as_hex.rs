use data_encoding::base16;
use serde::Serializer;

pub fn u8vec_as_hex<T, S>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
    where T: AsRef<[u8]>,
          S: Serializer
{
    serializer.serialize_str(&base16::encode(&data.as_ref()))
}
