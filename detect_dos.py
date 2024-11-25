import subprocess
import time
import re

MAX_PACKETS_THRESHOLD = 1000
SWITCH = 's1'

def detect_dos():
    while True:
        try:
            process = subprocess.Popen(
                ['ovs-ofctl', 'dump-flows', SWITCH],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, error = process.communicate()

            if error:
                print(f"[ERROR] Failed to fetch flow table: {error.decode('utf-8')}")
                continue

            flows = output.decode('utf-8')
            print(f"[DEBUG] Flow table output:\n{flows}")

            dos_source = parse_flows(flows)
            if dos_source:
                print(f"[ALERT] DoS attack detected from source: {dos_source}")
                apply_mitigation(dos_source)

        except Exception as e:
            print(f"[ERROR] Exception occurred: {e}")

        time.sleep(5)
      
# Parses the packet flow as it comes in for too many requests from one IP
def parse_flows(flows):
    flow_regex = re.compile(r'nw_src=([\d.]+).*n_packets=(\d+)')
    dos_candidates = {}

    for line in flows.split('\n'):
        match = flow_regex.search(line)
        if match:
            src_ip = match.group(1)
            packet_count = int(match.group(2))
            dos_candidates[src_ip] = packet_count

    for src_ip, packet_count in dos_candidates.items():
        print(f"[DEBUG] Source IP: {src_ip}, Packets: {packet_count}")
        if packet_count > MAX_PACKETS_THRESHOLD:
            return src_ip

    return None

# Updates rules to stop the DOS source
def apply_mitigation(dos_source):
    try:
        print(f"[DEBUG] Applying mitigation rule for source: {dos_source}")
        subprocess.Popen(
            ['ovs-ofctl', 'add-flow', SWITCH, f'priority=100,ip,nw_src={dos_source},actions=drop']
        )
        print(f"[INFO] Mitigation rule applied: Dropped packets from {dos_source}")
    except Exception as e:
        print(f"[ERROR] Failed to apply mitigation: {e}")

if __name__ == "__main__":
    detect_dos()
