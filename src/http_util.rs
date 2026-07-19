//! Small shared helpers for building `http_body_util` bodies, used by
//! both the fallback HTTPS server and the internal metrics API so the
//! two don't duplicate the same boilerplate.

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};

pub type ResponseBody = BoxBody<Bytes, std::convert::Infallible>;

pub fn empty_body() -> ResponseBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pub fn full_body(bytes: Bytes) -> ResponseBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}
