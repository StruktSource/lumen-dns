//! Lumen DNS daemon entry point.

use lumen_proto::{MAX_MESSAGE_SIZE, Query, Rcode, malformed_response};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

fn main() -> std::io::Result<()> {
    let bind = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:5353".into());
    if std::env::args().nth(1).as_deref() != Some("--bind") {
        println!(
            "{} DNS transport foundation. Run: lumen --bind 127.0.0.1:5353",
            lumen_core::PRODUCT_NAME
        );
        return Ok(());
    }
    let tcp = TcpListener::bind(&bind)?;
    let udp = UdpSocket::bind(&bind)?;
    thread::spawn(move || serve_tcp(&tcp));
    serve_udp(&udp, &bind)
}

fn answer(packet: &[u8]) -> Vec<u8> {
    Query::parse(packet).map_or_else(
        |_| malformed_response(packet),
        |query| query.response(Rcode::ServFail),
    )
}

fn serve_udp(socket: &UdpSocket, bind: &str) -> std::io::Result<()> {
    println!(
        "Lumen UDP/TCP transport listening on {bind}; resolver unavailable, returns SERVFAIL."
    );
    let mut buffer = [0_u8; MAX_MESSAGE_SIZE];
    loop {
        let (size, peer) = socket.recv_from(&mut buffer)?;
        let response = answer(&buffer[..size]);
        socket.send_to(&response, peer)?;
    }
}

fn serve_tcp(listener: &TcpListener) {
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming().flatten() {
        if active.fetch_add(1, Ordering::Relaxed) >= 64 {
            active.fetch_sub(1, Ordering::Relaxed);
            continue;
        }
        let active = Arc::clone(&active);
        thread::spawn(move || {
            let _ = serve_tcp_client(stream);
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn serve_tcp_client(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length > MAX_MESSAGE_SIZE {
        return Ok(());
    }
    let mut packet = vec![0; length];
    stream.read_exact(&mut packet)?;
    let response = answer(&packet);
    let response_length = u16::try_from(response.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS response exceeds TCP limit",
        )
    })?;
    stream.write_all(&response_length.to_be_bytes())?;
    stream.write_all(&response)
}
