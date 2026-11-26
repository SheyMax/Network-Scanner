from scapy.all import TCP, IP, ICMP, sr1

def fin_scan(port, ip, timeout):

    request = TCP(dport=port, flags="F")
    packet = IP(dst=ip) / request
    answer = sr1(packet, timeout=timeout, verbose=0)

    if answer is None:
        return {port : "opened|filtered"}

    if answer[TCP].flags == "R":
        return {port : "closed"}

    if answer.haslayer(ICMP):
        return {port : "filtered"}

    return {port : "unknow"}