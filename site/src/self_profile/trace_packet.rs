use std::time::UNIX_EPOCH;

use crate::trace::trace_packet::OptionalTrustedPacketSequenceId;
use crate::trace::track_event::NameField;
use crate::trace::{trace_packet::Data, ProcessDescriptor, Trace, TracePacket, TrackDescriptor};
use crate::trace::{track_event, TrackEvent};
use analyzeme::ProfilingData;
use prost::Message;

#[derive(serde::Deserialize, Debug)]
pub struct Opt {}

pub fn generate(self_profile_data: Vec<u8>, _: Opt) -> anyhow::Result<Vec<u8>> {
    let data = ProfilingData::from_paged_buffer(self_profile_data, None)
        .map_err(|e| anyhow::format_err!("{:?}", e))?;

    let packet = data
        .iter()
        .filter(|e| e.timestamp().map_or(false, |t| !t.is_instant()))
        .flat_map(|event| {
            let full_event = data.to_full_event(&event);

            vec![
                TracePacket {
                    timestamp: Some(
                        event
                            .start()
                            .unwrap()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64,
                    ),
                    data: Some(Data::TrackEvent(TrackEvent {
                        r#type: Some(track_event::Type::SliceBegin.into()),
                        track_uuid: Some(0),
                        name_field: Some(NameField::Name(full_event.label.clone().into_owned())),
                        ..Default::default()
                    })),
                    optional_trusted_packet_sequence_id: Some(
                        OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(1),
                    ),
                    ..Default::default()
                },
                TracePacket {
                    timestamp: Some(
                        event
                            .end()
                            .unwrap()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64,
                    ),
                    data: Some(Data::TrackEvent(TrackEvent {
                        r#type: Some(track_event::Type::SliceEnd.into()),
                        track_uuid: Some(0),
                        ..Default::default()
                    })),
                    optional_trusted_packet_sequence_id: Some(
                        OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(1),
                    ),
                    ..Default::default()
                },
            ]
        })
        .collect::<Vec<_>>();

    let trace = Trace {
        packet: [
            vec![TracePacket {
                data: Some(Data::TrackDescriptor(TrackDescriptor {
                    uuid: Some(0),
                    process: Some(ProcessDescriptor {
                        pid: Some(data.metadata().process_id as i32), // TODO: check pid range
                        process_name: None,
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            packet,
        ]
        .concat(),
    };

    let mut buf = Vec::with_capacity(trace.encoded_len());
    trace.encode(&mut buf).unwrap();

    Ok(buf)
}
