from scapy.all import UDP, IP, ICMP, sr1

def udp_scan(ip, port, timeout):

    request = UDP(dport=port)
    packet = IP(dst=ip) / request
    answer = sr1(packet, timeout=timeout, verbose=0)

    if answer == None:
        return {port : "opened|filtered"}

    if answer.haslayer(UDP):
        return {port : "opened"}

    elif answer.haslayer(ICMP):
        if answer[ICMP].type == 3 and answer[ICMP].code == 3:
            return {port : "closed"}
        else:
            return {port : "filtered"} # some ICMP messages indicate that a network device blocked the packet

    return {port : "unknow"} # unexpected behaviors