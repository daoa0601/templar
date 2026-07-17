# Configuration Guide: Cisco Catalyst 9300 Series

**Document ID:** HW-CFG-012
**Device:** Cisco Catalyst 9300 Series Switches

## Standard Port Configuration (Access Layer)

This is the standard configuration for an access port connecting to an end-user device.

```
interface GigabitEthernet1/0/1
 description ** User Access Port **
 switchport mode access
 switchport access vlan 100
 switchport voice vlan 200
 spanning-tree portfast
 spanning-tree bpduguard enable
```

- **`switchport access vlan 100`**: Assigns the port to the data VLAN (VLAN 100).
- **`switchport voice vlan 200`**: Assigns voice traffic from an IP phone to the voice VLAN (VLAN 200).
- **`spanning-tree portfast`**: Allows the port to transition to the forwarding state immediately, bypassing listening and learning states. Should only be used on ports connected to end devices.
- **`spanning-tree bpduguard enable`**: Protects against loops by shutting down the port if it receives a BPDU frame from another switch.

## Verifying DNS Configuration

The switch itself often gets its DNS settings from a DHCP server, but can also be configured statically.

To check the configured DNS servers, use the following command:

```
show run | include ip name-server
```

**Example Output:**
```
ip name-server 8.8.8.8 1.1.1.1
```

If this is incorrect, it can be changed in global configuration mode:

```
config t
no ip name-server 8.8.8.8 1.1.1.1
ip name-server <primary_dns_ip> <secondary_dns_ip>
```
