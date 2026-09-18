#[cfg(test)]
mod util_test;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use ipnet::IpNet;
use stun::agent::*;
use stun::attributes::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;
use stun::xoraddr::*;
use tokio::time::Duration;
use util::vnet::net::*;
use util::Conn;

use crate::agent::agent_config::{InterfaceFilterFn, IpFilterFn};
use crate::error::*;
use crate::network_type::*;

pub fn create_addr(_network: NetworkType, ip: IpAddr, port: u16) -> SocketAddr {
    /*if network.is_tcp(){
        return &net.TCPAddr{IP: ip, Port: port}
    default:
        return &net.UDPAddr{IP: ip, Port: port}
    }*/
    SocketAddr::new(ip, port)
}

pub fn assert_inbound_username(m: &Message, expected_username: &str) -> Result<()> {
    let mut username = Username::new(ATTR_USERNAME, String::new());
    username.get_from(m)?;

    if username.to_string() != expected_username {
        return Err(Error::Other(format!(
            "{:?} expected({}) actual({})",
            Error::ErrMismatchUsername,
            expected_username,
            username,
        )));
    }

    Ok(())
}

pub fn assert_inbound_message_integrity(m: &mut Message, key: &[u8]) -> Result<()> {
    let message_integrity_attr = MessageIntegrity(key.to_vec());
    Ok(message_integrity_attr.check(m)?)
}

/// Initiates a stun requests to `server_addr` using conn, reads the response and returns the
/// `XORMappedAddress` returned by the stun server.
/// Adapted from stun v0.2.
pub async fn get_xormapped_addr(
    conn: &Arc<dyn Conn + Send + Sync>,
    server_addr: SocketAddr,
    deadline: Duration,
) -> Result<XorMappedAddress> {
    let resp = stun_request(conn, server_addr, deadline).await?;
    let mut addr = XorMappedAddress::default();
    addr.get_from(&resp)?;
    Ok(addr)
}

const MAX_MESSAGE_SIZE: usize = 1280;

pub async fn stun_request(
    conn: &Arc<dyn Conn + Send + Sync>,
    server_addr: SocketAddr,
    deadline: Duration,
) -> Result<Message> {
    let mut request = Message::new();
    request.build(&[Box::new(BINDING_REQUEST), Box::new(TransactionId::new())])?;

    conn.send_to(&request.raw, server_addr).await?;
    let mut bs = vec![0_u8; MAX_MESSAGE_SIZE];
    let (n, _) = if deadline > Duration::from_secs(0) {
        match tokio::time::timeout(deadline, conn.recv_from(&mut bs)).await {
            Ok(result) => match result {
                Ok((n, addr)) => (n, addr),
                Err(err) => return Err(Error::Other(err.to_string())),
            },
            Err(err) => return Err(Error::Other(err.to_string())),
        }
    } else {
        conn.recv_from(&mut bs).await?
    };

    let mut res = Message::new();
    res.raw = bs[..n].to_vec();
    res.decode()?;

    Ok(res)
}

pub async fn local_interfaces(
    vnet: &Arc<Net>,
    interface_filter: &Option<InterfaceFilterFn>,
    ip_filter: &Option<IpFilterFn>,
    network_types: &[NetworkType],
    include_loopback: bool,
) -> HashSet<IpAddr> {
    local_interfaces_with(
        vnet,
        interface_filter,
        ip_filter,
        network_types,
        include_loopback,
        ipv6_source_among,
    )
    .await
}

/// `local_interfaces` with the OS's source selection handed in, so a test can stand in for it.
pub(crate) async fn local_interfaces_with(
    vnet: &Arc<Net>,
    interface_filter: &Option<InterfaceFilterFn>,
    ip_filter: &Option<IpFilterFn>,
    network_types: &[NetworkType],
    include_loopback: bool,
    pick: impl Fn(&[Ipv6Addr]) -> Option<Ipv6Addr>,
) -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    let interfaces = vnet.get_interfaces().await;

    let (mut ipv4requested, mut ipv6requested) = (false, false);
    for typ in network_types {
        if typ.is_ipv4() {
            ipv4requested = true;
        }
        if typ.is_ipv6() {
            ipv6requested = true;
        }
    }

    for iface in interfaces {
        if let Some(filter) = interface_filter {
            if !filter(iface.name()) {
                continue;
            }
        }

        let eligible: Vec<IpNet> = iface
            .addrs()
            .iter()
            .copied()
            .filter(|ipnet| {
                let ipaddr = ipnet.addr();
                (!ipaddr.is_loopback() || include_loopback)
                    && ((ipv4requested && ipaddr.is_ipv4()) || (ipv6requested && ipaddr.is_ipv6()))
                    && ip_filter
                        .as_ref()
                        .map(|filter| filter(ipaddr))
                        .unwrap_or(true)
            })
            .collect();
        // Of an interface's IPv6 addresses in one prefix, the one the OS sends from if that is one
        // of them, else all; `ipv6_one_per_prefix` says why. Asked among what the filters let
        // through: named an address a filter refuses, the group would thin to it and lose it.
        let ipv6_kept = ipv6_one_per_prefix(&eligible, &pick);
        for ipnet in eligible {
            match ipnet.addr() {
                IpAddr::V6(v6) if !ipv6_kept.contains(&v6) => {}
                ipaddr => {
                    ips.insert(ipaddr);
                }
            }
        }
    }

    ips
}

/// Of the IPv6 addresses one interface holds in one prefix, the one the OS sends from - or
/// all of them, when that cannot be told. Beside the temporary address that privacy extensions
/// rotate, a prefix usually carries a stable one the OS never picks as a source; a host
/// candidate for it hands the peer an identifier that outlives every rotation and that nothing
/// else this machine sends out ever shows. RFC 8445 §5.1.1.1 has the trackable addresses of an
/// interface and prefix left out once a privacy one is gathered; with no portable way to tell
/// the two apart, the OS's own choice stands in for that rule, best effort and not the rule
/// itself: `pick` asks the OS which address it sends from, and that address is kept alone if
/// it belongs to the group; if the OS names none of them - source selection resolved through
/// another interface, or could not be run - the whole group is kept. Every other interface and
/// prefix keeps its address. Grouped only under a known prefix of /64 or shorter: a /127 or
/// /128 is a prefix of its own, and an enumeration that reports no mask leaves an address at
/// /128, which keeps it rather than guessing. Link-local is left to the ip_filter.
pub(crate) fn ipv6_one_per_prefix(
    addrs: &[IpNet],
    pick: impl Fn(&[Ipv6Addr]) -> Option<Ipv6Addr>,
) -> HashSet<Ipv6Addr> {
    let mut groups: HashMap<(Ipv6Addr, u8), Vec<Ipv6Addr>> = HashMap::new();
    for ipnet in addrs {
        let IpNet::V6(net) = ipnet else {
            continue;
        };
        let v6 = net.addr();
        let link_local = v6.segments()[0] & 0xffc0 == 0xfe80;
        let key = if net.prefix_len() <= 64 && !link_local {
            (net.network(), net.prefix_len())
        } else {
            (v6, 128)
        };
        groups.entry(key).or_default().push(v6);
    }
    groups
        .into_values()
        .flat_map(|members| {
            if members.len() < 2 {
                return members;
            }
            // Only the OS's own answer thins a group. When it cannot be asked, or names an address
            // outside the group - the route to this prefix runs over another interface that shares
            // it - every address stays, as before: the first listed is on macOS the stable one.
            match pick(&members).filter(|c| members.contains(c)) {
                Some(chosen) => vec![chosen],
                None => members,
            }
        })
        .collect()
}

/// The address the OS sends from towards the prefix of `members`, which are one interface's.
/// A UDP `connect` runs the OS's own source address selection and sends nothing; with privacy
/// extensions on that is normally the temporary address, but the policy is the OS's to set.
/// The probe is bound to no interface: where two share the prefix, the route picks one of
/// them and the answer for the other is an address it does not hold.
pub(crate) fn ipv6_source_among(members: &[Ipv6Addr]) -> Option<Ipv6Addr> {
    let first = u128::from(*members.first()?);
    // An address in the prefix that is not one of ours: the first with one identifier bit
    // flipped, whichever bit gets it off the list.
    let dest = (0..64)
        .map(|bit| Ipv6Addr::from(first ^ (1u128 << bit)))
        .find(|d| !members.contains(d))?;
    let socket = std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((dest, 53)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V6(v6) => Some(v6),
        IpAddr::V4(_) => None,
    }
}

pub async fn listen_udp_in_port_range(
    vnet: &Arc<Net>,
    port_max: u16,
    port_min: u16,
    laddr: SocketAddr,
) -> Result<Arc<dyn Conn + Send + Sync>> {
    if laddr.port() != 0 || (port_min == 0 && port_max == 0) {
        return Ok(vnet.bind(laddr).await?);
    }
    let i = if port_min == 0 { 1 } else { port_min };
    let j = if port_max == 0 { 0xFFFF } else { port_max };
    if i > j {
        return Err(Error::ErrPort);
    }

    let port_start = rand::random::<u16>() % (j - i + 1) + i;
    let mut port_current = port_start;
    loop {
        let laddr = SocketAddr::new(laddr.ip(), port_current);
        match vnet.bind(laddr).await {
            Ok(c) => return Ok(c),
            Err(err) => log::debug!("failed to listen {}: {}", laddr, err),
        };

        port_current += 1;
        if port_current > j {
            port_current = i;
        }
        if port_current == port_start {
            break;
        }
    }

    Err(Error::ErrPort)
}
