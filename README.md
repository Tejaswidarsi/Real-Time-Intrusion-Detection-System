**_A Brief Overview of the Project_**
**Real-Time Network Intrusion Detection System**
Imagine a system that acts like a vigilant security guard for your network, constantly watching for suspicious activity and alerting you to potential attacks. That’s exactly what our project does—it’s a real-time Intrusion Detection System (IDS) designed to monitor network traffic, detect malicious behavior, and display the results on a web dashboard. Let me walk you through how it works, step by step.

First, we use Scapy, a powerful Python library that captures and analyzes network packets. To make this possible on a Windows system, Scapy relies on Npcap, a packet capture library that provides low-level access to your network interface, whether it’s Wi-Fi or Ethernet. Npcap enables Scapy to capture raw network traffic by tapping into the Data Link Layer (Layer 2), where it grabs Ethernet frames—these are the basic units of data transmission on a local network, containing details like MAC addresses and a payload. That payload is often an IP packet from the Network Layer (Layer 3), which carries the actual data we’re interested in, like source and destination IP addresses.

Here’s where the layers come into play: Scapy captures at Layer 2 by default because it gives us a full view of all network traffic, not just packets involving our device. This is crucial for an IDS—we want to see everything happening on the network, including attacks targeting other devices. If Npcap isn’t available, we fall back to Layer 3, capturing only IP packets involving our device, which limits our visibility but keeps the system running.

Once Scapy captures these packets, we filter for IP packets specifically—think of this as sifting through the network chatter to focus on internet traffic, like TCP, UDP, or ICMP packets. These packets are stored in a sliding window of up to 10 packets, which acts like a short-term memory, letting us analyze recent traffic patterns. For each packet, we extract features that help us determine if it’s normal or malicious. These features are:

protocol_type: Identifies the protocol, like TCP, UDP, or ICMP, so we know what kind of traffic we’re dealing with.
service: Maps the destination port to a service, like HTTP for port 80 or FTP for port 21, giving us context about the traffic’s purpose.
count: Tracks the number of connections to a destination IP, helping us spot spikes that might indicate a Denial-of-Service (DoS) attack.
serror_rate: Measures the rate of SYN errors (incomplete TCP handshakes) for a destination IP, a key indicator of SYN flood attacks.
srv_serror_rate: Similar to serror_rate, but specific to a destination IP and port combo, helping us detect service-specific attacks.
dst_host_serror_rate: Mirrors serror_rate for the destination host, reinforcing our detection of SYN-related anomalies.
dst_host_srv_serror_rate: Mirrors srv_serror_rate for the destination host and service, adding granularity to our analysis.
These features are inspired by the KDDTrain+ dataset, which we used to train a logistic regression model. If we’re training the model, we load the dataset, encode categorical features like protocol_type and service using a LabelEncoder, scale numerical features with a MinMaxScaler, and train the model to classify traffic as “Normal” or “Attack.” Otherwise, we load a pre-trained model and its preprocessors from saved files.

Back to the packet processing: we update connection and error counts for each packet. For example, if a TCP packet has a SYN flag but no ACK flag, we flag it as a potential SYN flood attack and increment our SYN error counters. We then check if there’s at least one packet in the window or if a second has passed since our last prediction—if so, it’s time to analyze.

We take the extracted features, encode and scale them to match our training data, and feed them into the logistic regression model. The model predicts whether the traffic is “Normal” or an “Attack,” along with a probability score. For instance, a high serror_rate might indicate a SYN flood, while a sudden spike in count could signal a DoS attack. The result—whether “Normal (OK)” or “Attack (Alert)”—is queued with details like the raw features, scaled features, probabilities, and a timestamp.

This queued data is sent to a Flask web application, which serves a dashboard at http://0.0.0.0:5000. The dashboard fetches the results via a /data endpoint and displays them in real-time, so you can see if an attack is happening right now. We also support offline analysis: you can feed the system a PCAP file—a saved capture of network traffic—and it will process the packets the same way, letting you test or analyze past incidents.

In summary, our IDS uses Scapy and Npcap to capture network traffic at Layer 2 for maximum visibility, extracts key features to detect attacks like SYN floods and DoS, predicts using a trained logistic regression model, and displays results on a Flask dashboard. It’s a robust system that monitors your network in real-time, ensuring you’re alerted to potential threats as they happen.
