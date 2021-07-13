use std::io::{Read, Write};

use crate::{
    request::to_vec,
    response::from_slice,
    types::{
        common::Operation,
        request::{QueryFunction, RequestPayload},
        response::{QueryResponsePayload, ResponseMessage, ResponsePayload, ResultStatus},
    },
};

#[allow(dead_code)]
pub struct Client<'a, T: Read + Write> {
    username: Option<String>,
    password: Option<String>,
    stream: &'a mut T,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    Unknown,
}

pub type Result<T> = std::result::Result<T, Error>;

impl<'a, T: Read + Write> Client<'a, T> {
    pub fn query(&mut self, operations: bool, objects: bool) -> Result<QueryResponsePayload>
    where
        T: Read + Write,
    {
        // Setup the request
        let mut wanted_info = Vec::new();
        operations.then(|| wanted_info.push(QueryFunction::QueryOperations));
        objects.then(|| wanted_info.push(QueryFunction::QueryObjects));

        // Serialize and write the request
        let req_bytes =
            to_vec(Operation::Query, RequestPayload::Query(wanted_info), None).map_err(|_| Error::Unknown)?;
        self.stream.write_all(&req_bytes).map_err(|_| Error::Unknown)?;

        // Read and deserialize the response
        let mut res_bytes = Vec::new();
        self.stream.read_to_end(&mut res_bytes).map_err(|_| Error::Unknown)?;

        // Process the response
        let mut res: ResponseMessage = from_slice(&res_bytes).map_err(|_| Error::Unknown)?;
        if res.header.batch_count == 1 && res.batch_items.len() == 1 {
            let item = &mut res.batch_items[0];

            if matches!(
                (&item.result_status, &item.operation, &item.payload),
                (
                    ResultStatus::Success,
                    Some(Operation::Query),
                    Some(ResponsePayload::Query(_))
                )
            ) {
                if let Some(payload) = item.payload.take() {
                    if let ResponsePayload::Query(payload) = payload {
                        return Ok(payload);
                    }
                }
            }
        }

        Err(Error::Unknown)
    }
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Read, Write};

    use super::Client;

    struct MockStream {
        pub response: Cursor<Vec<u8>>,
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::io::sink().write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.response.read(buf)
        }
    }

    #[test]
    fn test_query() {
        let use_case_response_hex = concat!(
            "42007B010000023042007A0100000048420069010000002042006A0200000004000000010000000042006B02000000040",
            "0000000000000004200920900000008000000004B7918AA42000D0200000004000000010000000042000F01000001D842",
            "005C0500000004000000180000000042007F0500000004000000000000000042007C01000001B042005C0500000004000",
            "000010000000042005C0500000004000000020000000042005C0500000004000000030000000042005C05000000040000",
            "00040000000042005C0500000004000000080000000042005C0500000004000000090000000042005C050000000400000",
            "00A0000000042005C05000000040000000B0000000042005C05000000040000000C0000000042005C0500000004000000",
            "0D0000000042005C05000000040000000E0000000042005C05000000040000000F0000000042005C05000000040000001",
            "00000000042005C0500000004000000110000000042005C0500000004000000120000000042005C050000000400000013",
            "0000000042005C0500000004000000140000000042005C0500000004000000150000000042005C0500000004000000160",
            "000000042005C0500000004000000180000000042005C0500000004000000190000000042005C05000000040000001A00",
            "0000004200570500000004000000010000000042005705000000040000000200000000420057050000000400000003000",
            "000004200570500000004000000040000000042005705000000040000000600000000"
        );
        let ttlv_wire = hex::decode(use_case_response_hex).unwrap();

        let mut stream = MockStream {
            response: Cursor::new(ttlv_wire),
        };

        let mut client = Client {
            username: None,
            password: None,
            stream: &mut stream,
        };
        dbg!(client.query(true, true).unwrap());
    }
}
