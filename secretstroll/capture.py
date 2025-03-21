import subprocess

from datetime import datetime
from time import sleep


def listen_to_trace(i):
    # set the name of the trace to be registered
    trace_name = "data_collection/trace_grid_{i}_{date}.pcap".format(i=str(i),
                                                                     date=datetime.now().strftime("%d_%H:%M:%S"))
    print("capturing " + trace_name)

    # Only intercept packets with tcp payloads with greater than 55
    tcpdump = subprocess.Popen(['tcpdump', '-w', trace_name, 'tcp'])
    sleep(2)

    # The choice of dojo is motivated by the list of pois given in Part 2. since dojo seems to be the most frequent poi
    query = subprocess.Popen("python3 client.py grid {i} -T dojo -t".format(i=str(i)), shell=True)
    query.communicate()
    sleep(2)

    query.terminate()
    tcpdump.terminate()

for j in range(20):
    # we iterate over all cells in the grid.
    for i in range(1, 101):
        listen_to_trace(i)
