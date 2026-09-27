#! /usr/bin/python3

from scapy.all import sniff, IP, TCP
import requests
from datetime import datetime
import json

SERVER_IP = "192.168.8.233"
connection_attempts = {}
flagged = []

# Load the previously flagged IPs incase the program is ever stopped so they are not written over
with open("flagged_IPs.json", "r") as f:
    events = json.load(f)

# ----- Traffic Reading Function ----- #

def read_traffic(packet):

    # If an IP address isn't involved then skip
    if IP not in packet:
        return

    # If the packet isn't headed for my server end the function and start on the next packet
    if packet[IP].dst != SERVER_IP:
        return

    # Ignore non-TCP packets
    if TCP not in packet:
        return

    # Put sources, ports and flags into respective variables
    source = packet[IP].src
    port = packet[TCP].dport
    flags = packet[TCP].flags

    # Print 'TCP scanners_IP -> port_number flags: flag_type'
    if TCP in packet:
        print(
            "TCP",
            source,
            "->",
            packet[TCP].dport,
            "flags:",
            packet[TCP].flags
        )

    # Run function to check if connections are suspicious
    detect_notify(source, port)

# ----- Detect and Notify Function ----- #

def detect_notify(source, port):

    # If an IP is new then add it to the attempts dict
    if source not in connection_attempts:
        connection_attempts.update({source: {port}})
    # If an IP is already in the attempts dict then add the new port it is trying to connect with to a set
    elif source in connection_attempts:
        connection_attempts[source].add(port)

    # If an IP is in the flagged list then go to the next IP
    for c in connection_attempts:
        if c in flagged:
            continue
        # If an IP has tried to connect with 10 different ports then add it to flagged
        elif len(connection_attempts[c]) >= 10:
            flagged.append(c)

            # Record the IP, current time, the 10 first ports and reason and add them to the events dict
            event = {
                "IP": c,
                "Datetime": datetime.now().isoformat(),
                "Ports": list(connection_attempts[c]),
                "Reason": "10 unique ports were contacted"
            }
            events.append(event)

            # Add the contents of events to the flagged IPs file to log and to load at the start of the program
            with open("flagged_IPs.json", "w") as f:
                json.dump(events, f, indent=4)

            # Alert the terminal and the ntfy server
            print(flagged, "has been flagged")
    
            requests.post( # Send a post request..
                "http://mainServersIPAndNtfyPort/URL", # To this URL and port..
                data = (f"{c} has been flagged") # With this text
            )

# ----- Sniffer function ----- #
    
sniff(
    iface="Ethernet",
    # Filter only for relevant traffic
    filter="ip and dst host 192.168.8.233 and not port 22",
    prn=read_traffic,    # Run detect and notify function over each packet
    store=False
)

