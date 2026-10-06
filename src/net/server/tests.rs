#![cfg(all(test, feature = "sync"))]
use std::io::{Cursor, Read, Write};

#[cfg(feature = "tokio")]
use tokio::sync::Mutex;

use crate::{
    net::{ClientBuilder, ServerBuilder},
    types::{
        common::*,
        response::{self},
    },
};

const TEST_OPERATIONS: [Operation; 22] = [
    Operation::Create,
    Operation::CreateKeyPair,
    Operation::Register,
    Operation::Rekey,
    Operation::Locate,
    Operation::Check,
    Operation::Get,
    Operation::GetAttributes,
    Operation::GetAttributeList,
    Operation::AddAttribute,
    Operation::ModifyAttribute,
    Operation::DeleteAttribute,
    Operation::ObtainLease,
    Operation::GetUsageAllocation,
    Operation::Activate,
    Operation::Revoke,
    Operation::Destroy,
    Operation::Archive,
    Operation::Recover,
    Operation::Query,
    Operation::Cancel,
    Operation::Poll,
];
const TEST_OBJECT_TYPES: [ObjectType; 5] = [
    ObjectType::Certificate,
    ObjectType::SymmetricKey,
    ObjectType::PublicKey,
    ObjectType::PrivateKey,
    ObjectType::Template,
];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MockStreamMode {
    Client,
    Server,
}

struct MockStream {
    pub bytes: Cursor<Vec<u8>>,
    pub mode: MockStreamMode,
}

impl MockStream {
    pub fn new() -> Self {
        Self {
            bytes: Cursor::new(vec![]),
            mode: MockStreamMode::Server,
        }
    }

    pub fn change_mode(&mut self, new_mode: MockStreamMode) {
        if new_mode != self.mode {
            self.bytes.set_position(0);
            self.mode = new_mode;
        }
    }
}

impl Write for MockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.mode {
            MockStreamMode::Client => std::io::sink().write(buf),
            MockStreamMode::Server => self.bytes.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for MockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.mode {
            MockStreamMode::Client => self.bytes.read(buf),
            MockStreamMode::Server => Ok(0),
        }
    }
}

#[test]
fn test_server() {
    // Configure the mock stream.
    let mut stream = MockStream::new();

    // Create a real KMIP server that "connects" to a mock network stream.
    let mut server = ServerBuilder::new(&mut stream).build();

    // Copied from test_client_query().
    let response_hex = concat!(
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
    let response_bytes = hex::decode(response_hex).unwrap();
    let response = response::from_slice(&response_bytes).unwrap();
    server.send_response(response.clone()).unwrap();
    server.send_response(response.clone()).unwrap();

    // Create a real KMIP client that "connects" to a mock network stream.
    stream.change_mode(MockStreamMode::Client);
    let mut client = ClientBuilder::new(&mut stream, "test").build();

    // First query should succeed
    let response_payload = client.query().unwrap();
    assert_eq!(response_payload.operations, Some(TEST_OPERATIONS.to_vec()));
    assert_eq!(response_payload.object_types, Some(TEST_OBJECT_TYPES.to_vec()));
    assert_eq!(response_payload.vendor_identification, None);
    assert_eq!(response_payload.server_information, None);

    // Second query should succeed
    let response_payload2 = client.query().unwrap();
    assert_eq!(response_payload2.operations, Some(TEST_OPERATIONS.to_vec()));
    assert_eq!(response_payload2.object_types, Some(TEST_OBJECT_TYPES.to_vec()));
    assert_eq!(response_payload2.vendor_identification, None);
    assert_eq!(response_payload2.server_information, None);
    assert_eq!(client.connection_error_count(), 0);

    // Third query should fail as we only served two responses.
    assert!(client.query().is_err());
}
