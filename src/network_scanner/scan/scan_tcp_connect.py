from scapy.all import TCP, IP, sr1, send, sr

def tcp_connect_scan(ip, port, timeout):

    request = TCP(dport=port, flags="S")
    packet = IP(dst=ip) / request
    answer = sr1(packet, timeout=timeout, verbose=0)

    if answer is None:
        return {port : "no answer"}

    elif not answer.haslayer(TCP):
        return {port : "unknow"}
    
    elif answer[TCP].flags == "SA":
        request = TCP(dport=answer[TCP].sport, sport=answer[TCP].dport, seq=answer[TCP].ack, ack=answer[TCP].seq+1, flags="A")
        packet = IP(dst=ip) / request
        send(packet, timeout=timeout)

        request = TCP(dport=answer[TCP].sport, sport=answer[TCP].dport, seq=answer[TCP].ack, ack=answer[TCP].seq+1, flags="FA")
        packet = IP(dst=ip) / request
        answered, unanswered = sr(packet, timeout=timeout, verbose=0)
        for sent, received in answered:
            if received[TCP].flags == "FA":
                request = TCP(dport=received[TCP].sport, sport=received[TCP].dport, seq=received[TCP].ack, ack=received[TCP].seq+1, flags="A")
                packet = IP(dst=ip) / request
                send(packet, timeout=timeout, verbose=0)

        return {port : "opened"}

    elif answer[TCP].flags == "R" or answer[TCP].flags == "RA":
        return {port : "closed"}

    return {port : "filtered"}