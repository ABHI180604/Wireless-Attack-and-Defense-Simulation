def classify_packet(packet):
    # Example logic (replace with real classification logic)
    if packet.haslayer('ARP'):
        return "ARP"
    elif packet.haslayer('DNS'):
        return "DNS"
    elif packet.haslayer('TCP'):
        return "TCP"
    elif packet.haslayer('UDP'):
        return "UDP"
    else:
        return "OTHER"

