"""Render host-isolation rules that keep the management channel up (F037).

NOT executed in this build. They are generated and unit-tested as text so reviewers can check the policy, and the
real-OS adapters will apply them. Principle: default-deny both directions; allow loopback, DNS to the named
resolver only for the management name, and TCP 443 to the management endpoints; keep rules tagged `halvard-isolate`
so release removes exactly them.
"""

def windows_rules(mgmt_ips, dns_server=None):
    cmds = ["netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"]
    for ip in mgmt_ips:
        cmds.append(f'netsh advfirewall firewall add rule name="halvard-isolate-mgmt-{ip}" dir=out action=allow '
                    f'remoteip={ip} protocol=TCP remoteport=443')
    if dns_server:
        cmds.append(f'netsh advfirewall firewall add rule name="halvard-isolate-dns" dir=out action=allow '
                    f'remoteip={dns_server} protocol=UDP remoteport=53')
    return cmds


def windows_release():
    return ['netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound',
            'netsh advfirewall firewall delete rule name=all group="halvard-isolate"']


def linux_nft(mgmt_ips, dns_server=None):
    lines = ["table inet halvard_isolate {", " chain out { type filter hook output priority -10; policy drop;",
             "  oif lo accept"]
    lines += [f"  ip daddr {ip} tcp dport 443 accept" for ip in mgmt_ips]
    if dns_server:
        lines.append(f"  ip daddr {dns_server} udp dport 53 accept")
    lines += [" }", " chain in { type filter hook input priority -10; policy drop;", "  iif lo accept",
              "  ct state established,related accept", " }", "}"]
    return "\n".join(lines)


def linux_release():
    return "nft delete table inet halvard_isolate"


def macos_pf(mgmt_ips, dns_server=None):
    """pf anchor loaded with: pfctl -E; pfctl -a halvard/isolate -f - . Default-deny both ways; loopback + management only."""
    rules = ["block drop all", "pass quick on lo0 all"]
    rules += [f"pass out quick proto tcp to {ip} port 443 keep state" for ip in mgmt_ips]
    if dns_server:
        rules.append(f"pass out quick proto udp to {dns_server} port 53 keep state")
    return ["\n".join(rules)]


def macos_release():
    return ["pfctl -a halvard/isolate -F all"]
