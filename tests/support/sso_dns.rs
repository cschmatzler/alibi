//! Controlled TXT service exercised through actual resolver packets.
use hickory_proto::{
    op::{Message, OpCode},
    rr::{RData, Record, rdata::TXT},
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
#[derive(Clone)]
pub(crate) struct Dns {
    pub(crate) address: SocketAddr,
    pub(crate) records: Arc<Mutex<Vec<Vec<String>>>>,
    pub(crate) queries: Arc<Mutex<Vec<String>>>,
}
pub(crate) async fn start() -> Dns {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let records = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let queries = Arc::new(Mutex::new(Vec::<String>::new()));
    let entries = records.clone();
    let seen = queries.clone();
    let _server = tokio::spawn(async move {
        let mut bytes = vec![0u8; 4096];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut bytes).await else {
                break;
            };
            let Ok(query) = Message::from_vec(&bytes[..length]) else {
                continue;
            };
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.metadata.recursion_available = true;
            response.metadata.authoritative = true;
            for question in query.queries {
                let name = question.name.clone();
                seen.lock()
                    .unwrap()
                    .push(name.to_utf8().trim_end_matches('.').to_owned());
                _ = response.add_query(question);
                for chunks in entries.lock().unwrap().iter() {
                    _ = response.add_answer(Record::from_rdata(
                        name.clone(),
                        0,
                        RData::TXT(TXT::new(chunks.clone())),
                    ));
                }
            }
            if let Ok(packet) = response.to_vec() {
                _ = socket.send_to(&packet, peer).await;
            }
        }
    });
    Dns {
        address,
        records,
        queries,
    }
}
