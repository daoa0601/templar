# Standard Operating Procedure: High TCP Retransmissions

**Document ID:** SOP-NET-001
**Topic:** Investigating and Resolving High TCP Packet Retransmissions

## 1. Initial Diagnosis

When high TCP retransmissions are detected by a monitoring tool (like `pcap-agent`), it indicates that packets are being lost somewhere between the source and the destination, forcing the sender to re-transmit the data. This leads to slow application performance and poor user experience.

**Severity Levels:**
- **Low (1-3%):** Monitor the situation. May be transient congestion.
- **Medium (3-7%):** Investigation required. There is a persistent issue.
- **High (7%+):** Critical impact. Immediate action is required.

## 2. Troubleshooting Steps

Follow these steps in order. Document your findings at each stage in the ticket.

### Step 2.1: Check Physical Layer

1.  **Identify the Interface:** Determine the switch/router ports for the affected source and destination IPs.
2.  **Check Port Statistics:** Log into the network device and check the interface counters for errors.
    - **Cisco IOS/NX-OS:** `show interface <interface_id>`
    - **Juniper Junos:** `show interfaces <interface_id> extensive`
3.  **Look For:**
    - `CRC errors`, `input errors`, `runts`, `giants`: These indicate a bad cable, faulty NIC, or SFP/transceiver issue.
    - `output drops`, `output queue drops`: These indicate network congestion. The interface is receiving traffic faster than it can send it.
4.  **Action:**
    - If physical errors are found, replace the cable and/or transceiver.
    - If output drops are high, proceed to Step 2.2.

### Step 2.2: Investigate Network Congestion

1.  **Analyze Traffic Patterns:** Use NetFlow or similar tools to identify the top talkers on the congested link.
2.  **Check QoS Policies:** Verify that Quality of Service (QoS) policies are correctly configured to prioritize critical traffic.
3.  **Increase Bandwidth:** If the link is legitimately over-utilized, an upgrade may be necessary. Escalate to the network planning team with supporting data.

## 3. Escalation

If the above steps do not resolve the issue, escalate the ticket to the Senior Network Engineering team. Include all diagnostic output from the `pcap-agent` and the results of the troubleshooting steps performed.
