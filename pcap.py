import argparse
import inspect
from pypacker import ppcap
from pypacker.layer12 import ethernet

parser = argparse.ArgumentParser(description='Process a pcap file.')
parser.add_argument('file', help='the pcap file to process')
parser.add_argument('-c', '--config', help='configuration file')
parser.add_argument('-a', '--available-properties', dest='availableproperties',
        help='list the available properties from the file', action='store_true')
args = parser.parse_args()
requestedattributes = []

if args.config is not None:
    with open(args.config) as c:
        for line in c:
            requestedattributes.append(line.rstrip())


pcap = ppcap.Reader(filename=args.file)

def isproperty(member):
    if inspect.ismethod(member):
        return False
    if inspect.isfunction(member):
        return False
    return True

printedattribues = []
generatingattribues = args.availableproperties

def traversePackets(prop, parentstring, packet):
    for attr in inspect.getmembers(prop, isproperty):
        key, value = attr
        if "upper_layer" == key:
            traversePackets(value, parentstring + "." + value.__class__.__name__, packet)
        if str.startswith(key, "_") or str.endswith(key, '_layer') or key.upper() == key:
            continue
        else:
            attributename = parentstring + "." + key
            if generatingattribues:
                if attributename not in printedattribues:
                    print(attributename)
                    printedattribues.append(attributename)
            else:
                if attributename in requestedattributes:
                    packet[attributename] = value
    return packet

for ts, buf in pcap:
    eth = ethernet.Ethernet(buf)
    packet = traversePackets(eth, "Ethernet", {})
    if not generatingattribues:
        packet['timestamp'] = ts
        print(packet)

pcap.close()
