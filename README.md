# SDN-Based Authentication and Access Control

## 1. Project Overview
This project integrates TCP socket programming with Software-Defined Networking (SDN) to control network access based on user authentication.

Authenticated users receive temporary network access. When a session expires, the system revokes access by removing the associated SDN forwarding rules.

## 2. Technologies Used
- Python 3
- TCP socket programming
- Mininet
- Open vSwitch (OVS)
- OpenFlow 1.3
- OS-Ken SDN controller
- Ubuntu

## 3. Architecture
The network contains two hosts connected to an Open vSwitch:
- Alice (h1): 10.0.0.1
- Bob (h2): 10.0.0.2
- Switch: s1

Main components:
- `auth_server.py`: Handles authentication, sessions, and expiry.
- `sdn_controller.py`: Processes access-control requests and manages forwarding rules.
- `run_controller.py`: Starts the SDN controller.
- `flow_manager.py`: Installs and removes OpenFlow rules.
- `topology.py`: Creates the Mininet network.

## 4. Access-Control Workflow
1. A user submits login credentials to the authentication server.
2. The server validates the credentials.
3. Successful authentication triggers an access-grant request to the controller.
4. The controller installs IPv4 and ARP forwarding rules.
5. The user can communicate through the switch while access is authorized.
6. When the session expires, the server requests access revocation.
7. The controller removes the user's rules. The default-drop rule blocks unmatched traffic.

## 5. Running the Project
Run commands from the project directory.

Start the authentication server in one terminal:
`sudo env SESSION_SECONDS=120 /usr/bin/python3 auth_server.py`

Start the controller in another terminal:
`sudo /usr/bin/python3 run_controller.py`

Start the Mininet topology in a third terminal:
`sudo /usr/bin/python3 topology.py`

Configure the switch to connect to the controller:
`sudo ovs-vsctl set-controller s1 tcp:127.0.0.1:6653`

The topology initializes with a default-drop rule. Authenticate a user to request network access.

## 6. Test Results

### Authenticated SDN forwarding
- Packets transmitted: 20
- Packets received: 20
- Packet loss: 0%
- Average round-trip time: 0.092 ms

A repeat test recorded:
- Packets transmitted: 20
- Packets received: 20
- Packet loss: 0%
- Average round-trip time: 0.083 ms

### Ordinary OVS forwarding baseline
- Packets transmitted: 20
- Packets received: 20
- Packet loss: 0%
- Average round-trip time: 0.098 ms

These are short individual tests. More repeated trials are needed before drawing conclusions about small latency differences.

### Session expiry
Authentication logs recorded successful login, session expiry, and network-access revocation events.

## 7. Evidence Files
- `performance_active.txt`: Initial authenticated forwarding test.
- `performance_sdn_repeat.txt`: Repeated authenticated forwarding test.
- `performance_static.txt`: Ordinary OVS forwarding baseline.
- `flows_default_deny.txt`: Default-deny flow-table snapshot.
- `evidence_final_flows.txt`: Final flow-table snapshot.
- `evidence_authentication.txt`: Authentication and session events.

## 8. Limitations
The measured latency values are from a small number of short tests. Results may vary between runs. The measurements do not establish a statistically significant performance difference between the two forwarding configurations.

## 9. Future Improvements
- Run more performance trials and report mean and variability.
- Test concurrent clients under load.
- Improve automated test and evidence collection.
- Extend the topology to support more hosts and access policies.
