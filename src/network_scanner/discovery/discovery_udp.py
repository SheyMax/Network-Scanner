from scapy.all import UDP, IP, sr, ICMP

def udp_discovery(ip, timeout):

    request = UDP(dport=80)
    packet = IP(dst=ip) / request

    detected = {}
    undetected = {}

    answered, unanswered = sr(packet, timeout=timeout, verbose=0)

    for sent, received in answered:

        if received.haslayer(ICMP):
            if received[ICMP].type == 3 and received[ICMP].code == 3: # ICMP type 3 code 3 -> port unreachable
                detected[received[IP].src] = {"protocol" : "UDP"}

        elif received.haslayer(UDP):
            detected[received[IP].src] = {"protocol" : "UDP"}

        else:
            undetected[received[IP].src] = {"protocol" : "UDP"}

    for result in unanswered:
        undetected[result[IP].dst] = {"protocol" : "UDP"}

    return (detected, undetected)
