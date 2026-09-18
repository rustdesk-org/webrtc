use super::*;

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn nets(s: &[&str]) -> Vec<IpNet> {
    s.iter().map(|n| n.parse().unwrap()).collect()
}

// One interface, one /64, a stable and a temporary address: only the one the OS sends from
// is kept, and the OS is asked, not the enumeration order.
#[test]
fn test_ipv6_one_per_prefix_keeps_the_address_the_os_sends_from() {
    let temporary = v6("2001:db8:1::a1b2:c3d4:e5f6:708");
    let kept = ipv6_one_per_prefix(
        &nets(&["2001:db8:1::1/64", "2001:db8:1::a1b2:c3d4:e5f6:708/64"]),
        |members| {
            assert_eq!(members.len(), 2);
            Some(temporary)
        },
    );
    assert_eq!(kept, HashSet::from([temporary]));
}

// Every other prefix keeps its address, and the OS is only asked about a group of more than
// one: a second /64, a unique-local one, and the /128s a tunnel hands out, which are prefixes
// of their own even when their first 64 bits agree.
#[test]
fn test_ipv6_one_per_prefix_keeps_every_other_prefix() {
    let kept = ipv6_one_per_prefix(
        &nets(&[
            "2001:db8:1::1/64",
            "2001:db8:2::1/64",
            "fd7a:115c::1/64",
            "2001:db8:9::1/128",
            "2001:db8:9::2/128",
        ]),
        |_| panic!("no group has more than one address"),
    );
    let want = [
        "2001:db8:1::1",
        "2001:db8:2::1",
        "fd7a:115c::1",
        "2001:db8:9::1",
        "2001:db8:9::2",
    ];
    assert_eq!(kept, want.iter().map(|a| v6(a)).collect());
}

// When the OS cannot be asked, or names an address outside the group, every address stays:
// nothing says which one is the temporary one, and the first listed is on macOS the stable one.
#[test]
fn test_ipv6_one_per_prefix_keeps_the_group_it_cannot_choose_from() {
    let addrs = nets(&["2001:db8:1::1/64", "2001:db8:1::2/64"]);
    let all = HashSet::from([v6("2001:db8:1::1"), v6("2001:db8:1::2")]);
    assert_eq!(ipv6_one_per_prefix(&addrs, |_| None), all);
    assert_eq!(
        ipv6_one_per_prefix(&addrs, |_| Some(v6("2001:db8:9::9"))),
        all
    );
}

// Ethernet and Wi-Fi on one LAN share a /64, and the route to it runs over one of them: asked
// about the other, the OS names an address of the first. That interface keeps both of its
// addresses; the one the route runs over keeps the OS's choice.
#[tokio::test]
async fn test_local_interfaces_keeps_an_interface_the_route_bypasses() {
    let temp_eth = v6("2001:db8:1::e:1");
    let net = Arc::new(Net::Ifs(vec![
        util::vnet::interface::Interface::new(
            "eth0".to_owned(),
            nets(&["2001:db8:1::e:0/64", "2001:db8:1::e:1/64"]),
        ),
        util::vnet::interface::Interface::new(
            "wlan0".to_owned(),
            nets(&["2001:db8:1::a:0/64", "2001:db8:1::a:1/64"]),
        ),
    ]));
    let ips = local_interfaces_with(&net, &None, &None, &[NetworkType::Udp6], false, |_| {
        Some(temp_eth)
    })
    .await;
    let want = [temp_eth, v6("2001:db8:1::a:0"), v6("2001:db8:1::a:1")];
    assert_eq!(ips, want.iter().map(|a| IpAddr::V6(*a)).collect());
}

// Link-local addresses are not grouped, so the OS is never asked about them; IPv4 is not
// this function's business; and nothing comes of nothing.
#[test]
fn test_ipv6_one_per_prefix_leaves_link_local_and_ipv4_alone() {
    let kept = ipv6_one_per_prefix(&nets(&["fe80::1/64", "fe80::2/64", "192.0.2.1/24"]), |_| {
        panic!("link-local is not a group")
    });
    assert_eq!(kept, HashSet::from([v6("fe80::1"), v6("fe80::2")]));
    assert!(ipv6_one_per_prefix(&[], |_| None).is_empty());
}

// The choice is made among the addresses the filters let through: a filter that refuses the
// address the OS would pick must leave the prefix its other address, not none. What the filter
// lets through here is a group of one, so the OS is not asked and the address stands.
#[tokio::test]
async fn test_local_interfaces_chooses_among_what_the_filter_allows() {
    let allowed = v6("2001:db8:7::2");
    let net = Arc::new(Net::Ifs(vec![util::vnet::interface::Interface::new(
        "eth0".to_owned(),
        nets(&["2001:db8:7::1/64", "2001:db8:7::2/64"]),
    )]));
    let ip_filter: Option<IpFilterFn> = Some(Box::new(move |ip| ip == IpAddr::V6(allowed)));
    let ips = local_interfaces(&net, &None, &ip_filter, &[NetworkType::Udp6], false).await;
    assert_eq!(ips, HashSet::from([IpAddr::V6(allowed)]));
}

#[tokio::test]
async fn test_local_interfaces() -> Result<()> {
    let vnet = Arc::new(Net::new(None));
    let interfaces = vnet.get_interfaces().await;
    let ips = local_interfaces(
        &vnet,
        &None,
        &None,
        &[NetworkType::Udp4, NetworkType::Udp6],
        false,
    )
    .await;

    let ips_with_loopback = local_interfaces(
        &vnet,
        &None,
        &None,
        &[NetworkType::Udp4, NetworkType::Udp6],
        true,
    )
    .await;
    assert!(ips_with_loopback.is_superset(&ips));
    assert!(!ips.iter().any(|ip| ip.is_loopback()));
    assert!(ips_with_loopback.iter().any(|ip| ip.is_loopback()));
    log::info!(
        "interfaces: {:?}, ips: {:?}, ips_with_loopback: {:?}",
        interfaces,
        ips,
        ips_with_loopback
    );
    Ok(())
}
