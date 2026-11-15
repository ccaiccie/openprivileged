# ADR-0003: Reaching customer networks — outbound-only on-prem collector with mTLS tunnel

Status: Accepted (planning)

## Context
Managed devices sit behind customer firewalls. MSPs will not open inbound ports or accept a per-customer VPN for a new vendor. Credentials and device sessions must stay inside the customer network as far as possible. Cloud Run cannot terminate raw SSH, and the broker also needs a TCP endpoint for the native `ssh` client.

## Options considered
1. Direct connection from the cloud NAT IP (customer allowlists it): simplest, but requires inbound rules and exposes management planes.
2. Site-to-site VPN per customer: heavy operations, overlapping RFC1918 ranges.
3. **On-prem collector (Python container) opening an outbound mTLS WebSocket tunnel to the broker**: no inbound ports, per-tenant scoping, runs rotation jobs locally.
4. Third-party tunnel (Tailscale/WireGuard mesh): extra vendor, per-node costs, weaker per-tenant isolation story.

## Decision
Option 3 as the default, option 1 as a "direct mode" for lab and internet-reachable devices. The collector enrols with a one-time token, receives a short-lived client certificate, and keeps one outbound `wss://` connection (443) to `gate.<domain>`. The broker sends "open session to host:port with credential reference" commands. Credentials are delivered to the collector over the tunnel only for the grant lifetime, held in memory, and never persisted. The native SSH endpoint (port 22) runs on a small Compute Engine instance group behind a TCP load balancer; web terminals use Cloud Run WebSockets.

## Consequences
+ No inbound firewall changes; overlapping IP space is handled by collector-per-tenant binding.
+ Rotation/verification can run on the customer LAN (works for management-plane-only reachability).
− Customer must run a container/VM; collector update and health become our support surface.
− Credential transiting the tunnel needs end-to-end protection (TLS + application-layer encryption to the collector's public key).
