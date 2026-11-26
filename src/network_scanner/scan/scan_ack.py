from scapy.all import TCP, IP, sr1

def ack_scan(port, ip, timeout):

    request = TCP(dport=port, flags="A")
    packet = IP(dst=ip) / request
    answer = sr1(packet, timeout=timeout, verbose=0)

    if answer is None:
        return {port : "filtered"}

    if answer.haslayer(TCP):
        if answer[TCP].flags == "R":
            return {port : "unfiltered"}
        else:
            return {port : "unknow"}

    return {port : "filtered"}