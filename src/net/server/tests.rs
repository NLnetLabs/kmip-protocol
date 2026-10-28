#![cfg(all(test, feature = "sync"))]
use std::io::{Cursor, Read, Write};

#[cfg(feature = "tokio")]
use tokio::sync::Mutex;

use crate::{
    net::{ClientBuilder, NetError, ServerBuilder, server::util::error_response},
    types::{
        common::*,
        response::{self, ResultStatus},
    },
};

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
    let response = error_response(
        Operation::Get,
        ResultStatus::OperationFailed,
        Some(response::ResultReason::ItemNotFound),
        None,
    )
    .unwrap();
    server.send_response(response.clone()).unwrap();
    server.send_response(response.clone()).unwrap();

    // Create a real KMIP client that "connects" to a mock network stream.
    stream.change_mode(MockStreamMode::Client);
    let mut client = ClientBuilder::new(&mut stream).build();

    // First query should succeed
    let res = client.get_key("i-dont-exist");
    assert!(matches!(res, Err(NetError::ItemNotFound(_))));

    // // Second query should succeed
    let res = client.get_key("i-dont-exist");
    assert!(matches!(res, Err(NetError::ItemNotFound(_))));

    // Third query should fail as we only served two responses.
    let res = client.get_key("i-dont-exist");
    assert!(matches!(res, Err(NetError::IoError(_))));
}
