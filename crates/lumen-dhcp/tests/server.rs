//! The server over real sockets on loopback: lease, publish, persist, expire.

use dhcproto::{
    Decodable, Decoder, Encodable,
    v4::{self, DhcpOption, HType, MessageType, Opcode, OptionCode},
    v6,
};
use lumen_config::{Dhcp, DhcpScope, DhcpScope6};
use lumen_resolver::Hosts;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, time::timeout};

fn free_udp(v6: bool) -> u16 {
    let socket = if v6 {
        std::net::UdpSocket::bind("[::1]:0")
    } else {
        std::net::UdpSocket::bind("127.0.0.1:0")
    }
    .unwrap();
    socket.local_addr().unwrap().port()
}

fn config(lease_file: std::path::PathBuf) -> Dhcp {
    Dhcp {
        enabled: true,
        domain: Some("home.lan".into()),
        lease_file: Some(lease_file),
        listen4: SocketAddr::from(([127, 0, 0, 1], free_udp(false))),
        listen6: SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], free_udp(true))),
        scopes: vec![DhcpScope {
            interface: None,
            subnet: "192.168.50.0/24".parse().unwrap(),
            server_address: "192.168.50.1".parse().unwrap(),
            range_start: "192.168.50.100".parse().unwrap(),
            range_end: "192.168.50.110".parse().unwrap(),
            router: Some("192.168.50.1".parse().unwrap()),
            dns: Vec::new(),
            lease_secs: 3600,
            reservations: Vec::new(),
        }],
        scopes6: vec![DhcpScope6 {
            interface: "lo".into(),
            prefix: "fd00:50::/64".parse().unwrap(),
            range_start: "fd00:50::100".parse().unwrap(),
            range_end: "fd00:50::110".parse().unwrap(),
            dns: vec!["fd00:50::1".parse().unwrap()],
            preferred_secs: 1800,
            valid_secs: 3600,
            reservations: Vec::new(),
        }],
        ..Dhcp::default()
    }
}

fn v4_message(kind: MessageType, requested: Option<std::net::Ipv4Addr>) -> v4::Message {
    let mut message = v4::Message::new_with_id(
        42,
        [0; 4].into(),
        [0; 4].into(),
        [0; 4].into(),
        [0; 4].into(),
        &[2, 0, 0, 0, 0, 9],
    );
    message.set_opcode(Opcode::BootRequest);
    message.set_htype(HType::Eth);
    let options = message.opts_mut();
    options.insert(DhcpOption::MessageType(kind));
    options.insert(DhcpOption::Hostname("Laptop".into()));
    if let Some(ip) = requested {
        options.insert(DhcpOption::RequestedIpAddress(ip));
    }
    message
}

async fn ask4(socket: &UdpSocket, server: SocketAddr, message: &v4::Message) -> v4::Message {
    socket
        .send_to(&message.to_vec().unwrap(), server)
        .await
        .unwrap();
    let mut buffer = [0u8; 1500];
    let (length, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
        .await
        .expect("the server answered")
        .unwrap();
    v4::Message::decode(&mut Decoder::new(&buffer[..length])).unwrap()
}

fn kind4(message: &v4::Message) -> MessageType {
    match message.opts().get(OptionCode::MessageType) {
        Some(DhcpOption::MessageType(kind)) => *kind,
        _ => panic!("no message type"),
    }
}

#[tokio::test]
async fn dhcpv4_leases_publish_a_name_and_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path().join("leases.db"));
    let hosts = Arc::new(Hosts::new(Some("home.lan")));
    let server = lumen_dhcp::start(&config, hosts.clone()).await.unwrap();
    let address = server.bound4[0];

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let offer = ask4(&client, address, &v4_message(MessageType::Discover, None)).await;
    assert_eq!(kind4(&offer), MessageType::Offer);
    let ip = offer.yiaddr();
    assert!("192.168.50.100".parse::<std::net::Ipv4Addr>().unwrap() <= ip);
    // An offer alone publishes nothing.
    assert!(hosts.is_empty());

    let ack = ask4(
        &client,
        address,
        &v4_message(MessageType::Request, Some(ip)),
    )
    .await;
    assert_eq!(kind4(&ack), MessageType::Ack);
    assert_eq!(ack.yiaddr(), ip);
    assert!(hosts.names().contains("laptop.home.lan."));

    // Stop, and start again over the same file: the lease and its name come back.
    drop(server);
    let again = Arc::new(Hosts::new(Some("home.lan")));
    let server = lumen_dhcp::start(&config, again.clone()).await.unwrap();
    assert!(again.names().contains("laptop.home.lan."));
    let renewed = ask4(
        &client,
        server.bound4[0],
        &v4_message(MessageType::Discover, None),
    )
    .await;
    assert_eq!(renewed.yiaddr(), ip, "the client keeps its address");

    // A release frees the address and withdraws the name.
    let mut release = v4_message(MessageType::Release, None);
    release.set_ciaddr(ip);
    client
        .send_to(&release.to_vec().unwrap(), server.bound4[0])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !again.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the name was withdrawn");
}

fn v6_message(
    kind: v6::MessageType,
    addr: Option<std::net::Ipv6Addr>,
    server: Option<Vec<u8>>,
) -> v6::Message {
    let mut message = v6::Message::new_with_id(kind, [7, 7, 7]);
    let options = message.opts_mut();
    options.insert(v6::DhcpOption::ClientId(vec![0, 1, 0, 1, 5]));
    if let Some(id) = server {
        options.insert(v6::DhcpOption::ServerId(id));
    }
    let mut ia = v6::IANA {
        id: 1,
        t1: 0,
        t2: 0,
        opts: v6::DhcpOptions::new(),
    };
    if let Some(addr) = addr {
        ia.opts.insert(v6::DhcpOption::IAAddr(v6::IAAddr {
            addr,
            preferred_life: 0,
            valid_life: 0,
            opts: v6::DhcpOptions::new(),
        }));
    }
    options.insert(v6::DhcpOption::IANA(ia));
    message
}

async fn ask6(socket: &UdpSocket, server: SocketAddr, message: &v6::Message) -> v6::Message {
    socket
        .send_to(&message.to_vec().unwrap(), server)
        .await
        .unwrap();
    let mut buffer = [0u8; 1500];
    let (length, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
        .await
        .expect("the server answered")
        .unwrap();
    v6::Message::decode(&mut Decoder::new(&buffer[..length])).unwrap()
}

fn lease6(message: &v6::Message) -> Option<std::net::Ipv6Addr> {
    message.opts().iter().find_map(|option| match option {
        v6::DhcpOption::IANA(ia) => ia.opts.iter().find_map(|inner| match inner {
            v6::DhcpOption::IAAddr(address) => Some(address.addr),
            _ => None,
        }),
        _ => None,
    })
}

#[tokio::test]
async fn dhcpv6_solicit_request_reply_over_a_socket() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config(dir.path().join("leases.db"));
    config.scopes.clear();
    // Loopback has no real interface to join; a fixed listen address skips that.
    config.scopes6[0].interface = if cfg!(target_os = "linux") {
        "lo"
    } else {
        "lo0"
    }
    .into();
    let hosts = Arc::new(Hosts::new(Some("home.lan")));
    let server = lumen_dhcp::start(&config, hosts.clone()).await.unwrap();
    let address = server.bound6.unwrap();

    let client = UdpSocket::bind("[::1]:0").await.unwrap();
    let advert = ask6(
        &client,
        address,
        &v6_message(v6::MessageType::Solicit, None, None),
    )
    .await;
    assert_eq!(advert.msg_type(), v6::MessageType::Advertise);
    let ip = lease6(&advert).unwrap();
    let Some(v6::DhcpOption::ServerId(server_id)) =
        advert.opts().get(v6::OptionCode::ServerId).cloned()
    else {
        panic!("no server id");
    };
    assert!(matches!(
        advert.opts().get(v6::OptionCode::DomainNameServers),
        Some(v6::DhcpOption::DomainNameServers(list)) if list == &config.scopes6[0].dns
    ));
    let reply = ask6(
        &client,
        address,
        &v6_message(v6::MessageType::Request, Some(ip), Some(server_id.clone())),
    )
    .await;
    assert_eq!(reply.msg_type(), v6::MessageType::Reply);
    assert_eq!(lease6(&reply), Some(ip));

    // The server identity is stable across a restart.
    drop(server);
    let server = lumen_dhcp::start(&config, hosts).await.unwrap();
    let advert = ask6(
        &client,
        server.bound6.unwrap(),
        &v6_message(v6::MessageType::Solicit, None, None),
    )
    .await;
    assert_eq!(
        advert.opts().get(v6::OptionCode::ServerId),
        Some(&v6::DhcpOption::ServerId(server_id))
    );
    assert_eq!(lease6(&advert), Some(ip));
}
