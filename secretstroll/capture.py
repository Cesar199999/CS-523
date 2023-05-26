import subprocess

# we iterate over all cells in the grid.
for i in range(1, 101):
    # set the name of the trace to be registered
    trace_name = "data_collection/trace_grid_{i}.pcap".format(i = str(i))
    print("capturing "+ trace_name)

    # use tcpdump to intercept tcp packets and use -w options to read it
    # use -s options to save only the first 64 bytes (containing headers)
    # only intercept packets with tcp payloads with greater than 55
    tcpdump = subprocess.Popen(['tcpdump', '-w', trace_name, '-s', '64', 'greater', '55', 'and', 'tcp'])

    # launch the query for dojo
    # the choice of dojo is motivated by the list of pois given in Part 2. since dojo seems to be the most frequent poi
    query = subprocess.Popen("python3 client.py grid {i} -T dojo -t".format(i = str(i)), shell=True)

    
    # read stdout and print it
    stdtout, stderr = query.communicate()

    print("Query over")

    tcpdump.terminate()

