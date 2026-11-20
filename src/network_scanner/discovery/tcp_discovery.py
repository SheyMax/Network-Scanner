from scapy.all import IP, TCP, sr, send

def tcp_syn_discovery(ip, timeout): 

        request = TCP(dport=80, flags="S") # flags="S" -> SYN
        packet = IP(dst=ip) / request

        detected = {}
        undetected = {}
        answered, unanswered = sr(packet, timeout=timeout, verbose=0)

        for sent, received in answered:

            if received[TCP].flags == "SA": # flags="SA" -> SYN-ACK
                detected[received[IP].src] = {"protocol" : "TCP SYN"}
                request = TCP(sport=received[TCP].dport, dport=received[TCP].sport, flags="R", seq=received[TCP].ack) # flags="R" -> RST
                packet = IP(dst=received[IP].src) / request
                send(packet, verbose=0)

            elif received[TCP].flags == "R":
                detected[received[IP].src] = {"protocol" : "TCP SYN"}

            else:
                undetected[received[IP].src] = {"protocol" : "TCP SYN"}

        for result in unanswered:
            undetected[result[IP].dst] = {"protocol" : "TCP SYN"}

        return (detected, undetected)


def tcp_ack_discovery(ip, timeout):

    request = TCP(dport=80, flags="A") 
    packet = IP(dst=ip) / request

    detected = {}
    undetected = {}

    answered, unanswered = sr(packet, timeout=timeout, verbose=0)

    for sent, received in answered:
        if received[TCP].flags == "R":
            detected[received[IP].src] = {"protocol" : "TCP ACK"}
        else:
            undetected[received[IP].src] = {"protocol" : "TCP ACK"}

    for result in unanswered:
        undetected[result[IP].dst] = {"protocol" : "TCP ACK"}

    return (detected, undetected)