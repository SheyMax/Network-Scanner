from scapy.all import IP, ICMP, sr

def icmp_discover(ip, timeout):

    request = ICMP(type=8) # type 8 -> ICMP echo request
    packet = IP(dst=ip) / request

    answered, unanswered = sr(packet, timeout=timeout, verbose=0)

    detected = {}
    undetected = {}

    for sent, received in answered:
        if received[ICMP].type == 0: # Verification ICMP echo reply
            detected[received[IP].src] = {"protocol" : "ICMP"}

    for result in unanswered:
        undetected[result[IP].dst] = {"protocol" : "ICMP"}

    return (detected, undetected)