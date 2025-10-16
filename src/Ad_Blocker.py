from scapy.all import DNS, DNSRR
import socket
import requests
import dns.resolver


def incarca_lista():
    domenii = set()
    with open("facebook.txt", "r") as f:
        for linie in f:
            linie = linie.strip()
            if linie.startswith('#') or linie == "":
                continue 
            tokeni = linie.split()
            if len(tokeni) != 2:
                continue
            ip, domeniu = tokeni[0], tokeni[1]
            if not domeniu.endswith('.'):
                domeniu += '.'
            domenii.add(domeniu.lower())
    with open("coinminer.txt", "r") as f:
        for linie in f:
            linie = linie.strip()
            if linie.startswith('#') or linie == "":
                continue 
            tokeni = linie.split()
            if len(tokeni) != 2:
                continue
            ip, domeniu = tokeni[0], tokeni[1]
            if not domeniu.endswith('.'):
                domeniu += '.'
            domenii.add(domeniu.lower())
    with open("adservers.txt", "r") as f:
        for linie in f:
            linie = linie.strip()
            if linie.startswith('#') or linie == "":
                continue 
            tokeni = linie.split()
            if len(tokeni) != 2:
                continue
            ip, domeniu = tokeni[0], tokeni[1]
            if not domeniu.endswith('.'):
                domeniu += '.'
            domenii.add(domeniu.lower())
    return domenii

blacklist = incarca_lista()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
port = 53
adresa = '0.0.0.0'
sock.bind((adresa, port))
domenii_salvate = set()

while True:
    print("cereri DNS:")
    data, adresa = sock.recvfrom(2048)
    # converitm payload-ul in pachet scapy
    packet = DNS(data)
    packet_dns = packet.getlayer(DNS)
    if packet_dns is not None and packet_dns.opcode == 0 and packet_dns.qr == 0:  # dns QUERY
        qname = packet_dns.qd.qname.decode().lower()
        print(qname)
        if qname in blacklist:
            ip_raspuns = '0.0.0.0'
            print("[BLOCAT]" + str(qname) + " -> " + str(ip_raspuns))
            if qname not in domenii_salvate:
                domenii_salvate.add(qname)
                with open("blocked_domains.txt", "a") as f:
                    f.write(qname + "\n")
        else:
            rasp = dns.resolver.resolve(qname, 'A')
            ip_raspuns = rasp[0].to_text()
            print("[ACCEPTAT]" + str(qname) + " -> " + str(ip_raspuns))

        dns_answer = DNSRR(
        rrname=packet_dns.qd.qname,
        ttl=330,
        type="A",
        rclass="IN",
        rdata=ip_raspuns)
        dns_response = DNS(
                        id = packet[DNS].id,
                        qr = 1,
                        aa = 0,
                        rcode = 0,
                        qd = packet.qd,
                        an = dns_answer)
        print('response:')
        print(dns_response.summary())
        sock.sendto(bytes(dns_response), adresa)

sock.close()


