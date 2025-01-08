from scapy.all import *

#check if ip address is valid
def check_ip_validity(ip_address: str) -> bool:
    try:
        #check if octets length is 4
        octets = ip_address.split(".")
        if len(octets) != 4:
            return False
        #check if each octet is in the range 0 to 255
        for octet in octets:
            if not octet.isdigit() or not 0 <= int(octet) <= 255:
                return False
        return True
    except:
        return False
    
#check port(s) validity:
def check_ports_validity(ports: str) -> bool:
    try:
        #check if each port is in the range 0 till 65536
        for port in ports:
            if not port.isdigit() or not 0 <= int(port) <= 65536:
                return False
        return True
    except:
        return False

#function where user enters filtering parameters
def input_filtering_params():
    while True:
        try:
            protocol_type = input("Enter protocol type (TCP, UDP): ").lower()
            if protocol_type not in ["tcp", "udp"]:
                print("Incorrect protocol type, must be tcp or udp. Try again.")
                continue
            ip_src = input("(Optinal)Enter source IPv4 address (x.x.x.x where x is from 0 till 255): ").strip()
            if ip_src and not check_ip_validity(ip_src):
                print("Wrong IPv4 address format. Try again.")
                continue
            ip_dest = input("(Optinal)Enter destination IPv4 address (x.x.x.x where x is from 0 till 255): ").strip()
            if ip_dest and not check_ip_validity(ip_dest):
                print("Wrong IPv4 address format. Try again.")
                continue
            ports = input("Enter port number(s): ").split(" ")
            if not check_ports_validity(ports):
                print("Wrong port format. Try again.")
                continue
            return protocol_type, ip_src, ip_dest, ports
        except Exception as e:
            print(f'Exception: {e}')
            continue

#function to sniff packets based on input parameters, and option to show in terminal and/or save in file
def show_packets(protocol: str, source_ip: str, destination_ip: str, ports: list):
    sniff_str = f'{protocol} '
    if ports:
        sniff_str += f"port {' or '.join(ports)} "
    if source_ip:
        sniff_str += f'and src host {source_ip} '
    if destination_ip:
        sniff_str += f'and dst host {destination_ip} '
    print(f"Sniffing filter: {sniff_str.strip()}")
    packets = sniff(filter=sniff_str, count = 10, prn = lambda p : p.show())

    #show packets in CLI
    for packet in packets:
        print(packet.show())
    
    #option to save in file
    save_file = input("Would you like to save results in file (y/n)?")
    if save_file == "y":
        wrpcap("packets.pcap", packets)
        print("Packets saved to packets.pcap file.")

def main():
    protocol, source_ip, dest_ip, ports = input_filtering_params()
    show_packets(protocol, source_ip, dest_ip, ports)

if __name__ == "__main__":
    main()


    