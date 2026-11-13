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
            next_server: None,
            boot_file: None,
            reservations: Vec::new(),
        }],
        scopes6: vec![DhcpScope6 {
            interface: Some("lo".into()),
            prefix: "fd00:50::/64".parse().unwrap(),
            range_start: "fd00:50::100".parse().unwrap(),
            range_end: "fd00:50::110".parse().unwrap(),
            dns: vec!["fd00:50::1".parse().unwrap()],
            preferred_secs: 1800,
            valid_secs: 3600,
            delegation: None,
            reconfigure: false,
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
    config.scopes6[0].interface = Some(
        if cfg!(target_os = "linux") {
            "lo"
        } else {
            "lo0"
        }
        .into(),
    );
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

fn tlv(code: u16, data: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
}

fn untlv(mut data: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while data.len() >= 4 {
        let code = u16::from_be_bytes([data[0], data[1]]);
        let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
        out.push((code, data[4..4 + length].to_vec()));
        data = &data[4 + length..];
    }
    out
}

#[tokio::test]
async fn dhcpv6_through_a_relay_agent_and_prefix_delegation_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config(dir.path().join("leases.db"));
    config.scopes.clear();
    // A network reached only through a relay: no interface of its own.
    config.scopes6[0].interface = None;
    config.scopes6[0].delegation = Some(lumen_config::PrefixDelegation {
        pool: "2001:db8:100::/40".parse().unwrap(),
        length: 56,
        reservations: Vec::new(),
    });
    let hosts = Arc::new(Hosts::new(Some("home.lan")));
    let server = lumen_dhcp::start(&config, hosts.clone()).await.unwrap();
    let address = server.bound6.unwrap();

    // The relay wraps a Solicit asking for an address and a prefix.
    let mut solicit = v6_message(v6::MessageType::Solicit, None, None);
    solicit.opts_mut().insert(v6::DhcpOption::IAPD(v6::IAPD {
        id: 9,
        t1: 0,
        t2: 0,
        opts: v6::DhcpOptions::new(),
    }));
    let inner = solicit.to_vec().unwrap();
    let mut forward = vec![12u8, 0];
    forward.extend_from_slice(&"fd00:50::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    forward.extend_from_slice(&"fe80::7".parse::<std::net::Ipv6Addr>().unwrap().octets());
    tlv(18, b"port-3", &mut forward);
    tlv(9, &inner, &mut forward);

    let client = UdpSocket::bind("[::1]:0").await.unwrap();
    client.send_to(&forward, address).await.unwrap();
    let mut buffer = [0u8; 1500];
    let (length, _) = timeout(Duration::from_secs(3), client.recv_from(&mut buffer))
        .await
        .expect("the relay got an answer")
        .unwrap();
    let wrapped = &buffer[..length];
    assert_eq!(wrapped[0], 13, "a Relay-reply");
    assert_eq!(
        &wrapped[2..18],
        &"fd00:50::1".parse::<std::net::Ipv6Addr>().unwrap().octets()
    );
    let options = untlv(&wrapped[34..]);
    assert!(
        options
            .iter()
            .any(|(code, data)| *code == 18 && data == b"port-3"),
        "interface id echoed"
    );
    let (_, inner) = options.iter().find(|(code, _)| *code == 9).unwrap();
    let advert = v6::Message::decode(&mut Decoder::new(inner)).unwrap();
    assert_eq!(advert.msg_type(), v6::MessageType::Advertise);
    assert!(lease6(&advert).is_some());
    let prefix = advert
        .opts()
        .iter()
        .find_map(|option| match option {
            v6::DhcpOption::IAPD(ia) => ia.opts.iter().find_map(|inner| match inner {
                v6::DhcpOption::IAPrefix(p) => Some((p.prefix_ip, p.prefix_len)),
                _ => None,
            }),
            _ => None,
        })
        .expect("a delegated prefix");
    assert_eq!(prefix.1, 56);

    // Ask for it for real (directly, with the server identifier) and restart.
    let Some(v6::DhcpOption::ServerId(server_id)) =
        advert.opts().get(v6::OptionCode::ServerId).cloned()
    else {
        panic!("no server id");
    };
    let mut request = v6_message(v6::MessageType::Request, lease6(&advert), Some(server_id));
    request.opts_mut().insert(v6::DhcpOption::IAPD(v6::IAPD {
        id: 9,
        t1: 0,
        t2: 0,
        opts: {
            let mut opts = v6::DhcpOptions::new();
            opts.insert(v6::DhcpOption::IAPrefix(v6::IAPrefix {
                preferred_lifetime: 0,
                valid_lifetime: 0,
                prefix_len: prefix.1,
                prefix_ip: prefix.0,
                opts: v6::DhcpOptions::new(),
            }));
            opts
        },
    }));
    let reply = ask6(&client, address, &request).await;
    assert_eq!(reply.msg_type(), v6::MessageType::Reply);
    let snapshot = server.handle().snapshot();
    assert!(snapshot.leases.iter().any(|l| l.prefix_len == Some(56)));
    drop(server);
    let server = lumen_dhcp::start(&config, hosts).await.unwrap();
    let snapshot = server.handle().snapshot();
    assert!(
        snapshot
            .leases
            .iter()
            .any(|l| l.prefix_len == Some(56) && l.ip == std::net::IpAddr::from(prefix.0)),
        "the delegated prefix is restored"
    );
}

#[tokio::test]
async fn network_boot_options_reach_the_client() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config(dir.path().join("leases.db"));
    config.scopes6.clear();
    config.scopes[0].next_server = Some("192.168.50.9".parse().unwrap());
    config.scopes[0].boot_file = Some("undionly.kpxe".into());
    let server = lumen_dhcp::start(&config, Arc::new(Hosts::new(Some("home.lan"))))
        .await
        .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let offer = ask4(
        &client,
        server.bound4[0],
        &v4_message(MessageType::Discover, None),
    )
    .await;
    assert_eq!(offer.siaddr().to_string(), "192.168.50.9");
    assert!(matches!(
        offer.opts().get(OptionCode::BootfileName),
        Some(DhcpOption::BootfileName(file)) if file == b"undionly.kpxe"
    ));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_standby_server_copies_leases_stays_quiet_then_covers_for_a_failed_primary() {
    use lumen_config::{DhcpFailover, FailoverRole};
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret");
    std::fs::write(&secret, "a shared failover secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let link = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let side = |role, name: &str| {
        let mut config = config(dir.path().join(name));
        config.scopes6.clear();
        config.failover = Some(DhcpFailover {
            role,
            peer: (role == FailoverRole::Primary).then_some(link),
            listen: (role == FailoverRole::Secondary).then_some(link),
            secret_file: secret.clone(),
            takeover_secs: 2,
            reserve_percent: 20,
        });
        config
    };
    let secondary = lumen_dhcp::start(
        &side(FailoverRole::Secondary, "b.db"),
        Arc::new(Hosts::new(Some("home.lan"))),
    )
    .await
    .unwrap();
    let primary = lumen_dhcp::start(
        &side(FailoverRole::Primary, "a.db"),
        Arc::new(Hosts::new(Some("home.lan"))),
    )
    .await
    .unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let offer = ask4(
        &client,
        primary.bound4[0],
        &v4_message(MessageType::Discover, None),
    )
    .await;
    let ip = offer.yiaddr();
    let ack = ask4(
        &client,
        primary.bound4[0],
        &v4_message(MessageType::Request, Some(ip)),
    )
    .await;
    assert_eq!(kind4(&ack), MessageType::Ack);

    // The standby learns the lease.
    let standby = secondary.handle();
    timeout(Duration::from_secs(8), async {
        while !standby
            .snapshot()
            .leases
            .iter()
            .any(|l| l.ip == std::net::IpAddr::from(ip))
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the lease was copied");
    assert!(
        !standby.snapshot().failover.unwrap().active,
        "quiet while the primary lives"
    );
    // And says nothing to clients while the primary is alive.
    client
        .send_to(
            &v4_message(MessageType::Discover, None).to_vec().unwrap(),
            secondary.bound4[0],
        )
        .await
        .unwrap();
    let mut buffer = [0u8; 1500];
    assert!(
        timeout(Duration::from_millis(800), client.recv_from(&mut buffer))
            .await
            .is_err()
    );

    // The primary fails; after the takeover time the standby answers, keeps the address of the
    // client it knows, and gives a new device an address from the end of the range.
    drop(primary);
    tokio::time::sleep(Duration::from_millis(3500)).await;
    assert!(standby.snapshot().failover.unwrap().active);
    let again = ask4(
        &client,
        secondary.bound4[0],
        &v4_message(MessageType::Discover, None),
    )
    .await;
    assert_eq!(again.yiaddr(), ip);
    let mut newcomer = v4_message(MessageType::Discover, None);
    newcomer.set_chaddr(&[2, 0, 0, 0, 0, 77]);
    let fresh = ask4(&client, secondary.bound4[0], &newcomer).await;
    assert!(
        u32::from(fresh.yiaddr())
            >= u32::from("192.168.50.109".parse::<std::net::Ipv4Addr>().unwrap()),
        "from the reserve: {}",
        fresh.yiaddr()
    );
}

#[tokio::test]
async fn a_partner_with_the_wrong_secret_is_not_trusted() {
    use lumen_config::{DhcpFailover, FailoverRole};
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, text: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    };
    let link = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let side = |role, name: &str, secret| {
        let mut config = config(dir.path().join(name));
        config.scopes6.clear();
        config.failover = Some(DhcpFailover {
            role,
            peer: (role == FailoverRole::Primary).then_some(link),
            listen: (role == FailoverRole::Secondary).then_some(link),
            secret_file: secret,
            takeover_secs: 2,
            reserve_percent: 20,
        });
        config
    };
    let secondary = lumen_dhcp::start(
        &side(
            FailoverRole::Secondary,
            "b.db",
            write("one", "the first shared secret"),
        ),
        Arc::new(Hosts::new(Some("home.lan"))),
    )
    .await
    .unwrap();
    let primary = lumen_dhcp::start(
        &side(
            FailoverRole::Primary,
            "a.db",
            write("two", "a different shared secret"),
        ),
        Arc::new(Hosts::new(Some("home.lan"))),
    )
    .await
    .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let offer = ask4(
        &client,
        primary.bound4[0],
        &v4_message(MessageType::Discover, None),
    )
    .await;
    ask4(
        &client,
        primary.bound4[0],
        &v4_message(MessageType::Request, Some(offer.yiaddr())),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let standby = secondary.handle().snapshot();
    assert!(
        standby.leases.is_empty(),
        "nothing is copied from a stranger"
    );
    assert!(
        standby.failover.unwrap().active,
        "a stranger does not keep the standby quiet"
    );
}

#[tokio::test]
async fn a_client_that_accepted_is_told_to_renew_with_a_signed_reconfigure() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config(dir.path().join("leases.db"));
    config.scopes.clear();
    // The device's address is the loopback address, so the message can reach the test client.
    config.scopes6[0].prefix = "::1/128".parse().unwrap();
    config.scopes6[0].range_start = "::1".parse().unwrap();
    config.scopes6[0].range_end = "::1".parse().unwrap();
    config.scopes6[0].interface = None;
    config.scopes6[0].reconfigure = true;
    let client = UdpSocket::bind("[::1]:0").await.unwrap();
    config.client_port6 = client.local_addr().unwrap().port();
    let server = lumen_dhcp::start(&config, Arc::new(Hosts::new(Some("home.lan"))))
        .await
        .unwrap();
    let address = server.bound6.unwrap();

    let mut solicit = v6_message(v6::MessageType::Solicit, None, None);
    solicit.opts_mut().insert(v6::DhcpOption::ReconfAccept);
    let advert = ask6(&client, address, &solicit).await;
    let ip = lease6(&advert).unwrap();
    let Some(v6::DhcpOption::ServerId(server_id)) =
        advert.opts().get(v6::OptionCode::ServerId).cloned()
    else {
        panic!("no server id");
    };
    // Before the client agreed there is nothing to send.
    assert!(server.handle().reconfigure(ip.into(), false).is_err());
    let mut request = v6_message(v6::MessageType::Request, Some(ip), Some(server_id));
    request.opts_mut().insert(v6::DhcpOption::ReconfAccept);
    let reply = ask6(&client, address, &request).await;
    assert!(
        reply
            .opts()
            .iter()
            .any(|o| matches!(o, v6::DhcpOption::Authentication(a) if a.info.first() == Some(&1)))
    );

    let snapshot = server.handle().snapshot();
    assert!(snapshot.leases.iter().any(|l| l.reconfigurable));
    server.handle().reconfigure(ip.into(), false).unwrap();
    let mut buffer = [0u8; 1500];
    let (length, from) = timeout(Duration::from_secs(3), client.recv_from(&mut buffer))
        .await
        .expect("a Reconfigure arrived")
        .unwrap();
    assert_eq!(from, address, "it comes from the server port");
    let message = v6::Message::decode(&mut Decoder::new(&buffer[..length])).unwrap();
    assert_eq!(message.msg_type(), v6::MessageType::Reconfigure);
    assert!(matches!(
        message.opts().get(v6::OptionCode::ReconfMsg),
        Some(v6::DhcpOption::ReconfMsg(v6::MessageType::Renew))
    ));
    // IPv4 leases cannot be reconfigured.
    assert!(
        server
            .handle()
            .reconfigure("192.168.50.100".parse().unwrap(), false)
            .is_err()
    );
}
