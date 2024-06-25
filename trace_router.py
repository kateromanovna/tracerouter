import socket
import subprocess
import re
from ipwhois import IPWhois

class TraceRouter:

    def __init__(self, destinations: str | list[str], hops_limit: int = 5):
        self.hops = hops_limit
        self.destinations = destinations if isinstance(destinations, list) else [destinations]

    def trace(self, destination: str, hops_limit: int) -> str:
        try:
            print(f"trace to {destination}")
            result = subprocess.check_output(["tracert", "-h", str(hops_limit), destination], shell=True)
            return result
        except subprocess.CalledProcessError:
            print("Failed to connect")

    def get_domain(self, ip: str) -> str:
        try:
            domain = socket.gethostbyaddr(ip)[0]
            return domain
        except socket.herror:
            return "Unknown"

    def get_more_inf(self, ip: str) -> None:
        try:
            whois_info = IPWhois(ip)
            lookup_results = whois_info.lookup_rdap()
            print(f"AS number and info: {lookup_results['asn']}\n{lookup_results['asn_description']}")
        except Exception as error:
            print(f"Failed to fetch AS information for {ip}: {error}")

    def process_traces(self) -> None:
        for t in self.destinations:
            print('------------------------')
            print(t)
            trace_data = self.trace(t, self.hops).decode('cp866')

            if trace_data:
                ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

                for line in trace_data.split('\n'):
                    ips = ip_regex.findall(line)
                    if ips:
                        domain = self.get_domain(ips[0])
                        print(f"IP: {ips[0]}, Domain: {domain}")
                        self.get_more_inf(ips[0])
            else:
                print("No data")

if __name__ == '__main__':
    tracer = TraceRouter(destinations=['lenta.ru', 'programforyou.ru', 'ekaterinburg.leroymerlin.ru'], hops_limit=5)
    tracer.process_traces()