from scapy.all import TCP, IP, sr1, send

def syn_scan(port, ip, timeout):

    request = TCP(dport=port, flags="S")
    packet = IP(dst=ip) / request
    answer = sr1(packet, timeout=timeout, verbose=0)

    if answer is None:
        return {port : "filtered"}

    elif answer[TCP].flags == "R" or answer[TCP].flags == "RA":
        return {port : "closed"}

    elif answer[TCP].flags == "SA":
        request = TCP(dport=answer[TCP].sport, sport=answer[TCP].dport, seq=answer[TCP].ack, flags="R")
        packet = IP(dst=ip) / request
        send(packet, timeout=timeout, verbose=0)
        return {port : "opened"}

    else:
        return {port : "filtered"}