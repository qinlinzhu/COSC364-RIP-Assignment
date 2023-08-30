import select
import sys
import socket
import time
import random
from math import floor

# GLOBALS
HOST = "127.0.0.1"
INFINITY = 16
# Two versions of timers, one that follows specs and a faster one for testing
TIMER = 30
TIMEOUT_TIMER = 180
GARBAGE_TIMER = 120
# TIMER = 5
# TIMEOUT_TIMER = 30
# GARBAGE_TIMER = 20



class Output:
    def __init__(self, initstring):
        attr = initstring.split('-')
        test_id = int(attr[0])
        if (test_id > 255) or (test_id < 0):
            raise Exception("Invalid Router ID of " + str(attr[0]))
        self.dest_id = test_id
        test_metric = int(attr[1])
        if (test_metric > 16) or (test_metric < 1):
            raise Exception("Invalid Metric of " + str(attr[1]))
        self.metric = test_metric
        test_port = int(attr[2])
        if (test_port > 64000) or (test_port < 1024):
            raise Exception("Invalid Port of " + str(attr[2]))
        self.port = test_port



class Entry:
    def __init__(self, router_id, metric, dest_one, dest, s_timer=time.time(), rc_flag=False, timed_out=False,
    g_timer=None):
        self.router_id = router_id # router id in the network
        self.metric = metric
        self.dest_one = dest_one # first destination to get to router id (neighbour)
        self.dest = dest
        self.s_timer = s_timer
        self.rc_flag = rc_flag
        self.timed_out = timed_out
        self.g_timer = g_timer



def routing_table_generator(self_id, input_ports, outputs_list):
    routing_table = {self_id: Entry(self_id, 0, None, input_ports[0], None, None, False, None)}
    for output in outputs_list:
        routing_table[output.dest_id] = Entry(output.dest_id, output.metric, output.dest_id, output.port)
    return routing_table



def config(config_file):
    # Reads a config file and returns:
    # the router's ID as an int,
    # the input ports as a list of ints,
    # and the outputs as a list of strings
    f = open(config_file, "r")
    self_id = f.readline().split()
    ports = [] # ports must occur only once
    input_ports = f.readline()
    input_ports = [x.strip(",") for x in input_ports.split()]
    outputs_list = []
    outputs = f.readline()
    outputs = [x.strip(",") for x in outputs.split()]

    if (self_id[0] == 'router-id:') and (255 > int(self_id[1]) > 0):
        self_id = int(self_id[1])
    else:
        raise Exception("Invalid or Missing router-id line")
    

    if input_ports[0] == 'input-ports:':
        del input_ports[0]
        for i in input_ports:
            if 1024 <= int(i) <= 64000:
                ports.append(int(i))
            else:
                raise Exception("Invalid Input Port")
    else:
        raise Exception("Invalid or missing input-ports line")
    

    if outputs[0] == 'outputs:':
        del outputs[0]
        for output in outputs:
            outputs_list.append(Output(output))
    else:
        print("Invalid or missing outputs line")
        exit(1)
    return self_id, ports, outputs_list



def create_sockets(input_ports):
    # takes a list of input ports and returns a list of sockets bound to those ports
    sockets = []
    try:
        for port in input_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((HOST, int(port)))
            sockets.append(sock)
    except socket.error as msg:
        print('Socket Error. Message: ' + str(msg))
        sys.exit()
    return sockets



def generate_payload(routing_table):
    payload = bytearray()
    for self_ids in routing_table:
        block = bytearray(20)
        for i in range(20):
            block[i] = 0x00
        block[1] = 0x02
        block[7] = self_ids
        block[19] = routing_table[self_ids].metric
        payload.extend(block)
    return payload



def send_updates(self_id, outputs_list, output_socket, routing_table):
    header = bytearray(4)
    header[0] = 0x02
    header[1] = 0x02
    header[2] = 0x00
    header[3] = self_id
    for output in outputs_list:
        payload = generate_payload(routing_table)
        packet = header
        packet.extend(payload)
        output_socket.sendto(packet, (HOST, output.port))



def wait_message(sockets):
    readable, writable, error = select.select(sockets, [], [], 1)
    if len(readable) == 0:
        return None
    packets = []
    for available in readable:
        packet, addr = available.recvfrom(1024)
        packets.append(bytes(packet))
        print("message received from " + str(packet[3]))
    return packets



def routing_table_printer(routing_table, self_id):
    print('\n')
    print(f" routing_table of router: {self_id}")
    print(f" {'Dest':<8}{'1st Dest':^10}{'Metric':^10}{'T timer':^10}{'T/O':^10}{'G timer':^10}")
    print('-' * 70)
    for key in sorted(routing_table.keys()):
        try:
            t = round(time.time() - routing_table[key].s_timer)
            g = round(time.time() - routing_table[key].g_timer)
        except TypeError:
            t = 0
            g = 0
    if routing_table[key].dest_one is None:
        fd = 0
    else:
        fd = routing_table[key].dest_one

    if routing_table[key].timed_out is True:
        to = "YES"
    else:
        to = "NO"

    print(f" {routing_table[key].router_id:<8}{fd:^10}{routing_table[key].metric:^10}{t:^10}{to:^10}{g:^10}")



def process(message, routing_table):
    """Takes a byte array message and parses and processes it"""

    if message[0] != 0x02:
        print("Invalid command section (must be 2)")
        return None

    if message[1] != 0x02:
        print("Invalid Version Number (must be 2)")
        return None
    
    sender_id = int(message[2] << 8 | message[3]) # router id of the sender
    payload = message[4:]
    new_entry_list = []

    for i in range(floor(len(payload) / 20)):
        if payload[20 * i] is None:
            break
        
        entry = payload[20 * i:20 * (i + 1)]
        if len(entry) < 20:
            print("entry not a multiple of 20")
            print(len(payload))
            break

        address_family_id = int(entry[0] << 8 | entry[1])
        route_tag = int(entry[2] << 8 | entry[3])

        if address_family_id != 2:
            print("invalid address family identifier")
            continue


        dest_id = int(entry[4] << 24 | entry[5] << 16 | entry[6] << 8 | entry[7]) # router id of final destination
        subnet_mask = int(entry[8] << 24 | entry[9] << 16 | entry[10] << 8 | entry[11])
        next_hop = int(entry[12] << 24 | entry[13] << 16 | entry[14] << 8 | entry[15])
        metric = int(entry[16] << 24 | entry[17] << 16 | entry[18] << 8 | entry[19])
        new_entry = Entry(dest_id, metric, sender_id, dest_id)
        new_entry_list.append(new_entry)

    return new_entry_list



def routing_table_updater(routing_table, new_entries, self_id, input_ports):
    for entry in new_entries:
        # if neighbour sends package and neighbour not in routing table
        # get sender id and create entry in table
        if (entry.router_id == self_id) and (entry.metric < INFINITY):
            if entry.metric != 0:
                if entry.router_id not in routing_table:
                    entry.rc_flag = True
                    routing_table[entry.dest_one] = entry
                    routing_table[entry.dest_one].router_id = entry.dest_one
                    entry.s_timer = time.time()
                    entry.timed_out = False
                    routing_table_printer(routing_table, self_id)
                else:
                    routing_table[entry.dest_one] = entry
                    routing_table[entry.dest_one].router_id = entry.dest_one
                    entry.s_timer = time.time()
                    entry.timed_out = False
        
        # if new router found and not in routing table add router
        elif (entry.router_id not in routing_table) and ((entry.metric < INFINITY) and (entry.metric != 0)):
            try:
                routing_table.update({entry.router_id: entry})
                routing_table[entry.router_id].metric += routing_table[entry.dest_one].metric
                routing_table[entry.router_id].s_timer = time.time()
                routing_table[entry.router_id].timed_out = False
                routing_table[entry.router_id].rc_flag = True
                routing_table_printer(routing_table, self_id)
            except KeyError:
                continue


        elif entry.router_id in routing_table:
            # if router in table and sender is router. it is neighbours
            if (entry.dest_one == routing_table[entry.router_id].router_id) and (entry.metric < INFINITY):
                routing_table[entry.router_id].s_timer = time.time()
                routing_table[entry.router_id].timed_out = False

            elif entry.metric < INFINITY:
                # if router in table and metric not infinity. if sender in table and router metric smaller than router
                # metric in table update entry
                if (entry.dest_one in routing_table) and (entry.metric < routing_table[entry.router_id].metric):
                    m = entry.metric + routing_table[entry.dest_one].metric
                    if m < routing_table[entry.router_id].metric:
                        routing_table.update({entry.router_id: entry})
                        routing_table[entry.router_id].metric = entry.metric
                        routing_table[entry.router_id].metric += routing_table[entry.dest_one].metric
                        routing_table[entry.router_id].s_timer = time.time()
                        routing_table[entry.router_id].timed_out = False
                        routing_table[entry.router_id].rc_flag = True
                        routing_table_printer(routing_table, self_id)
                elif m >= INFINITY:
                    routing_table[entry.router_id].metric = INFINITY
                    routing_table[entry.router_id].timed_out = True
                    routing_table[entry.router_id].rc_flag = True
                    routing_table_printer(routing_table, self_id)
                    # if garbage timer not exist for expired entry update garbage timer
                    if routing_table[entry.router_id].g_timer is None:
                        routing_table[entry.router_id].g_timer = time.time()
                else:
                    routing_table[entry.router_id].s_timer = time.time()
                    routing_table[entry.router_id].timed_out = False

        # if first destination to router in table first destination is neighbour
        elif entry.dest_one in routing_table:
            # if the router entry metric is infinity it has expired update to infinity in own table
            if entry.router_id != self_id:
                if (entry.metric == INFINITY) and (routing_table[entry.router_id].metric != INFINITY):
                    neighbour_list = []
                    for neighbour in routing_table:
                        if neighbour != self_id:
                            neighbour_list.append(routing_table[neighbour].dest_one)
                    # checks if neighbour is a router in table
                    if entry.router_id not in neighbour_list:
                        routing_table[entry.router_id].metric = INFINITY
                        routing_table[entry.router_id].timed_out = True
                        routing_table[entry.router_id].s_timer = time.time()
                        routing_table[entry.router_id].rc_flag = True
                        routing_table_printer(routing_table, self_id)
                        # if garbage timer not exist for expired entry update garbage timer
                        if routing_table[entry.router_id].g_timer is None:
                            routing_table[entry.router_id].g_timer = time.time()
                        # removes path to router when not existant is first destination to router
                        for f_dest in neighbour_list:
                            if f_dest not in routing_table.keys():
                                for dests in routing_table:
                                    if routing_table[dests].dest_one == f_dest:
                                        routing_table[dests].metric = INFINITY
                                        routing_table[dests].timed_out = True
                                        routing_table[dests].s_timer = time.time()
                                        routing_table[dests].rc_flag = True
                                        if routing_table[dests].g_timer is None:
                                            routing_table[dests].g_timer = time.time()
    return routing_table



def timer_out(routing_table, self_id):
    for router_id in routing_table:
        if routing_table[router_id].router_id == self_id:
            continue
        elif time.time() - routing_table[router_id].s_timer > TIMEOUT_TIMER:
            if routing_table[router_id].timed_out is False:
                routing_table[router_id].metric = INFINITY
                routing_table[router_id].timed_out = True
                routing_table[router_id].rc_flag = True
                routing_table[router_id].g_timer = time.time()
                
                routing_table_printer(routing_table, self_id)
                print('table updated entry timed out')
    return routing_table



def garbage(routing_table, self_id):
    copy = routing_table.copy()
    for router_id in copy:
        if copy[router_id].router_id == self_id:
            continue
        elif (copy[router_id].timed_out == True) and (copy[router_id].g_timer != None):
            if copy[router_id].g_timer < time.time() - GARBAGE_TIMER:
                del routing_table[router_id]

                routing_table_printer(routing_table, self_id)
                print('table updated deleted entry')

    return routing_table



def rc_checker(self_id, outputs_list, output_socket, routing_table):
    rc_table = {}
    for router_id in routing_table:
        if routing_table[router_id].rc_flag is True:
            rc_table.update({routing_table[router_id].router_id: routing_table[router_id]})
            send_updates(self_id, outputs_list, output_socket, rc_table)
            routing_table[router_id].rc_flag = False
            print('interrupt flag raised sent table')
    return routing_table



def main():
    self_id, input_ports, outputs_list = config(sys.argv[1])
    sockets = create_sockets(input_ports)
    routing_table = routing_table_generator(self_id, input_ports, outputs_list)
    output_socket = sockets[0]
    send_updates(self_id, outputs_list, output_socket, routing_table)
    routing_table_printer(routing_table, self_id)
    t = time.time()
    while True:
        if (time.time() - t) >= TIMER:
            t += random.uniform(0.8 * TIMER, 1.2 * TIMER)
            send_updates(self_id, outputs_list, output_socket, routing_table)
            routing_table_printer(routing_table, self_id)

        packets = wait_message(sockets)
        if packets is not None:
            for packet in packets:
                new_entries = process(packet, routing_table)
                routing_table = routing_table_updater(routing_table, new_entries, self_id, input_ports)
                routing_table = rc_checker(self_id, outputs_list, output_socket, routing_table)
                routing_table_printer(routing_table, self_id)
                print('received new entry')
                
        routing_table = timer_out(routing_table, self_id)
        routing_table = rc_checker(self_id, outputs_list, output_socket, routing_table)
        routing_table = garbage(routing_table, self_id)
main()