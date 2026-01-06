mod kmip_10_use_case_11_1_access_control;
mod timestamp_support;
mod kmip_10_use_case_12_1_query;
mod kmip_10_use_case_3_1_basic_functionality;
mod kmip_10_use_case_4_1_key_lifecycle;
mod kmip_10_use_case_8_1_create_key_pair;

mod kmip_11_test_case_12_1_query;
mod kmip_11_test_case_16_1_discover_versions;
mod kmip_11_test_case_17_1_attribute_handling;

#[allow(non_snake_case)]
mod kmip_13_test_case_5_9_8_1_CS_AC_M_1_13;
#[allow(non_snake_case)]
mod kmip_13_test_case_5_9_9_1_CS_RNG_M_1_13;

mod handle_unspecified_input;
mod locate_key_by_name_and_type;

mod util {
    use crate::{
        ttlv::{fast_scan::FastScanner, format::Formatter},
        types::request::RequestMessage,
    };

    /// Check that the given request message can be serialized and
    /// deserialized correctly.
    pub fn assert_req_ser_de(req: RequestMessage, expected_req_wire_hex: &str) {
        // Serialize to wire format.
        let mut buffer = Box::<[u8]>::new_uninit_slice(4096);
        let mut formatter = Formatter::new(&mut buffer);
        let actual_request_hex = match req.format(&mut formatter) {
            Ok(_) => hex::encode_upper(formatter.filled().as_flattened()),
            Err(err) => panic!("Failed to encode KMIP request as TTLV: {}", err),
        };

        // Verify that the generated wire bytes match the expected wire bytes.
        assert_eq!(
            expected_req_wire_hex, actual_request_hex,
            "expected hex (left) differs to the generated hex (right)"
        );

        // Deserialize the generated wire bytes.
        let buffer = formatter.filled().as_flattened();
        let mut scanner = FastScanner::new(buffer).unwrap();
        let dereq = RequestMessage::fast_scan(&mut scanner).unwrap();

        // Verify that the deserialized request matches the original request.
        assert_eq!(req, dereq);
    }
}
