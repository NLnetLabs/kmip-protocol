use criterion::{Criterion, criterion_group, criterion_main};

use kmip_protocol::types::{
    common::{Operation, UniqueBatchItemID},
    request::{
        self, Authentication, BatchCount, BatchItem, MaximumResponseSize, ProtocolVersionMajor, ProtocolVersionMinor,
        QueryFunction, RequestHeader, RequestMessage, RequestPayload,
    },
};

fn bench(c: &mut Criterion) {
    let use_case_request = RequestMessage(
        // Tag: 0x420078, Type: 0x01 (Structure)
        RequestHeader(
            //   Tag: 0x420077, Type: 0x01 (Structure)
            request::ProtocolVersion(
                //     Tag: 0x420069, Type: 0x01 (Structure)
                ProtocolVersionMajor(1), //       Tag: 0x42006A, Type: 0x02 (Integer), Data: 0x00000001 (1)
                ProtocolVersionMinor(0), //       Tag: 0x42006B, Type: 0x02 (Integer), Data: 0x00000000 (0)
            ), //
            Some(MaximumResponseSize(256)), //     Tag: 0x420050, Type: 0x02 (Integer), Data: 0x00000100 (256)
            Option::<Authentication>::None, //
            BatchCount(1),                  //     Tag: 0x42000D, Type: 0x02 (Integer), Data: 0x00000001 (1)
        ), //
        vec![BatchItem(
            //   Tag: 0x42000F, Type: 0x01 (Structure)
            Operation::Query, //     Tag: 0x42005C, Type: 0x05 (Enumeration). Data: 0x00000018
            Option::<UniqueBatchItemID>::None, //
            RequestPayload::Query(vec![
                //     Tag: 0x420079, Type: 0x01 (Structure)
                QueryFunction::QueryOperations, //       Tag: 0x420074, Type: 0x05 (Enumeration), Data: 0x00000001
                QueryFunction::QueryObjects,    //       Tag: 0x420074, Type: 0x05 (Enumeration), Data: 0x00000002
            ]),
        )],
    );

    let ttlv_bytes = kmip_ttlv::ser::to_vec(&use_case_request).unwrap();

    let mut group = c.benchmark_group("Deserializer comparison");
    group.throughput(criterion::Throughput::Bytes(ttlv_bytes.len() as u64));
    let bytes = ttlv_bytes.clone();
    group.bench_function("fast_deserializer", move |b| b.iter(|| fast(&bytes)));
    let bytes = ttlv_bytes.clone();
    group.bench_function("slow_deserializer", move |b| b.iter(|| slow(&bytes)));
    group.finish();
}

fn fast(ttlv_bytes: &[u8]) {
    let mut scanner = kmip_protocol::ttlv::fast_scan::FastScanner::new(ttlv_bytes).unwrap();
    let req = RequestMessage::fast_scan(&mut scanner).unwrap();

    assert_eq!(
        req.header().protocol_version(),
        &request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0))
    );
}

fn slow(ttlv_bytes: &[u8]) {
    let req: RequestMessage = kmip_ttlv::de::from_slice(ttlv_bytes).unwrap();

    assert_eq!(
        req.header().protocol_version(),
        &request::ProtocolVersion(ProtocolVersionMajor(1), ProtocolVersionMinor(0))
    );
}

criterion_group!(benches, bench);
criterion_main!(benches);
