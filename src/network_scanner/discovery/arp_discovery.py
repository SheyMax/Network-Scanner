from scapy.all import ARP, Ether, srp

def arp_disc(ip, timeout):

    request = ARP(op=1, pdst=ip) # op=1 -> ARP request
    frame = Ether(dst="ff:ff:ff:ff:ff:ff") / request
    answered, unanswered = srp(frame, verbose=0, timeout=timeout)

    detected = {}
    not_detected = {}

    for sent, received in answered:
        detected[received.psrc] = {"mac" : received.hwsrc,
                                   "protocol" : "arp"}

    for packet in unanswered:
        not_detected[packet.pdst] = {"protocol" : "arp"}

    return (detected, not_detected)