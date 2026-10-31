from scapy.all import ARP, Ether, srp

def arp_disc(ip, timeout):

    request = ARP(op=1, pdst=ip) # op=1 -> ARP request
    frame = Ether(dst="ff:ff:ff:ff:ff:ff") / request

    answered, unanswered = srp(frame, verbose=0, timeout=timeout)

    detected = {}
    undetected = {}

    for sent, received in answered:
        detected[received[ARP].psrc] = {"mac" : received[ARP].hwsrc,
                                   "protocol" : "ARP"}

    for result in unanswered:
        undetected[result[ARP].pdst] = {"protocol" : "ARP"}

    return (detected, undetected)