import yaml
import subprocess
import networkx as nx
import matplotlib.pyplot as plt
import string
import random
import shutil
from collections import defaultdict
import os
import re
import sys
import time
import threading
from python_terraform import *

class TerraformMachine(threading.Thread):
    def __init__(self, machine_directory, machine_number, command):
        super(TerraformMachine, self).__init__()
        self.machine_directory = machine_directory
        self.ip = None
        self.machine_number = machine_number
        self.command = command

    def run(self):
        if self.command == "create":
            self.create()
        if self.command == "destroy":
            self.destroy()

    def create(self):
        print(f"Creating machine #{self.machine_number}")
        tf = Terraform(working_dir=self.machine_directory)
        tf.init()
        tf.apply(skip_plan=True)
        print(f"Done creating machine #{self.machine_number}")
        self.refresh()


    def refresh(self):
        tf = Terraform(working_dir=self.machine_directory)
        stdout = "null"
        while "null" in stdout:
            _, stdout, _ = tf.refresh()
            time.sleep(1)
        ips = re.findall(r'"(.*?)"', stdout)
        for ip in ips:
            if '::' not in ip:
                print(ip)
                self.ip = ip
                break

    def destroy(self):
        print(f"Destroying machine #{self.machine_number}")
        tf = Terraform(working_dir=self.machine_directory)
        tf.destroy()
        print(f"Done destroying machine #{self.machine_number}")

class Machine(threading.Thread):
    def __init__(self, machine_directory):
        super(Machine, self).__init__()
        self.machine_directory = machine_directory
        self.machine_number = self.machine_directory.split('_')[1]
        self.terraform_machine = None

    def execute_terraform_command(self, command):
        self.terraform_machine = TerraformMachine(self.machine_directory, self.machine_number, command)
        self.terraform_machine.start()

    def run(self):
        self.write_connections_to_playbook()
        self.write_provisioning_script()


    def setup(self, machine_ip_connection_list, connections, ip_addr, max_node):
        self.whitelisted_machines = connections
        self.machine_ip_connection_list = machine_ip_connection_list
        self.host_ip = ip_addr
        self.max_node = max_node
        self.start()

    def write_provisioning_script(self):
        orig = './provision.sh'
        target = f'./machine_{self.machine_number}/provision.sh'
        shutil.copyfile(orig, target)
        command = None
        with open(target) as f:
            command = f.readline()

        with open(target, 'w') as f:
            command = command.replace("{{IP}}", self.terraform_machine.ip)
            f.write(command)


    def write_connections_to_playbook(self):
        print(self.machine_ip_connection_list)
        print(self.whitelisted_machines)
        connections_to_ips = [self.machine_ip_connection_list[connection] for connection in self.whitelisted_machines]
        if self.machine_number == "0":
            print(f"Whitelisting {self.host_ip} on machine zero")
            connections_to_ips.append(self.host_ip)
        print(f"Whitelisting ips: {connections_to_ips} on host {self.terraform_machine.ip}")
        data = None
        with open(f'machine_{self.machine_number}/playbook.yml') as f: 
            data = yaml.load(f)
        if self.machine_number != "0":
            data[0]['vars']['ufw'] = dict()
            data[0]['vars']['ufw']['ips'] = connections_to_ips

        # Reorder
        data[0]['roles'] = list(set(data[0]['roles']))


        if int(self.machine_number) == self.max_node and not 'flags' in data[0]['roles']:
            data[0]['roles'].append('flags')
            data[0]['vars']['flags'] = list()
            data[0]['vars']['flags'].append(''.join(random.choice(string.ascii_lowercase) for i in range(10)))

        if not 'ufw' in data[0]['roles'] and self.machine_number != "0":
            # Make sure the ufw is first role so that it doesn't overrule over ssh rules
            data[0]['roles'].insert(0, 'ufw')

        with open(f'machine_{self.machine_number}/playbook.yml', 'w') as f:
            yaml.dump(data, f, default_flow_style=False)





def read_connections():
    connections = defaultdict(list)
    with open("connections.txt") as f:
        content = f.read().splitlines()
        for line in content:
            src, dest = line.split("-")
            dest_int = int(dest) - 1
            src_int = int(src) - 1
            real_dest = str(dest_int)
            real_src = str(src_int)
            connections[real_src].append(real_dest)

    
    G = nx.DiGraph()
    for src, destinations in connections.items():
        for dest in destinations:
            G.add_edge(src, dest)

    nx.draw(G, with_labels=True)
    plt.savefig("Graph.png", format="PNG")

    int_nodes = [int(x) for x in G.nodes]
    max_node = max(int_nodes) - 1

    reverse_connections = defaultdict(list)

    for (machine, connection_list) in connections.items():
        for connection in connection_list:
            reverse_connections[connection].append(machine)
    reverse_connections['0'] = []

    return reverse_connections, max_node

def create(machine_dirs, ip_addr):
    ips = {}
    machine_list = []
    print("Setting up Terraform Machines")
    for machine_dir in machine_dirs:
        machine = Machine(machine_dir)
        machine_list.append(machine)
        machine.execute_terraform_command("create")

    # Wait for threads to finish
    for machine in machine_list:
        machine.terraform_machine.join()

    print("Finished setting up Terraform Machines")

    # Update IP list
    for machine in machine_list:
        ips[machine.machine_number] = machine.terraform_machine.ip

    connections, max_node = read_connections()

    print("Writing ansible scripts for machines")
    for machine in machine_list:
        machine.setup(ips, connections[machine.machine_number], ip_addr, max_node)


    print("Waiting 90 seconds for all machines to release apt")
    time.sleep(90)

    provision(machine_dirs)


def destroy(machine_dirs):
    machine_list = []
    print("Destroying up Terraform Machines")
    for machine_dir in machine_dirs:
        machine = Machine(machine_dir)
        machine_list.append(machine)
        machine.execute_terraform_command("destroy")

    # Wait for threads to finish
    for machine in machine_list:
        machine.terraform_machine.join()

    print("Finished destroying up Terraform Machines")


class ProvisionCommand(threading.Thread):
    def __init__(self, machine_path, script_path, log_path):
        super(ProvisionCommand, self).__init__()
        self.machine_path = machine_path
        self.script_path = script_path
        self.log_path = log_path

    def run(self):
        with open(self.log_path, 'w') as f:
            p = subprocess.Popen(f"bash {self.script_path}", shell = True, stdout = f, stderr=f, cwd=self.machine_path)
            p.communicate()

        


def provision(machine_dirs):
    machine_list = []

    print("Provisioning machines")
    for machine_dir in machine_dirs:
        machine = Machine(machine_dir)
        machine_list.append(machine)

    processes = []
    for machine in machine_list:
        machine_path = os.getcwd() + machine.machine_directory[1:]
        provision_script_path = machine_path + "/provision.sh"
        provision_log_path = machine_path + "/log.provision"
        p = ProvisionCommand(machine_path, provision_script_path, provision_log_path)
        p.start()
        processes.append(p)

    for p in processes:
        p.join()

if __name__ == '__main__':
    machine_dirs = [f.path for f in os.scandir('.') if f.is_dir() and 'machine' in f.path]

    method = sys.argv[1]
    if method == "create":
        create(machine_dirs, "192.168.0.1")

    if method == "destroy":
        destroy(machine_dirs)

    if method == "graph":
        read_connections()

    if method == "provision":
        provision(machine_dirs)

def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix), end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()

    # if method == 'create':
    #     for machine in machine_list:
    #         ips[machine.machine_number] = machine.ip
    #     with open("connections.txt") as f:
    #         content = f.read().splitlines()
    #         for line in content:
    #             src, dest = line.split(",", 1)
    #             dest = dest[1:-1]
    #             dest_machines = dest.split(',')
    #             connections[src] = dest_machines
        
    #     reverse_connections = defaultdict(list)
    #     for (machine, connection_list) in connections.items():
    #         for connection in connection_list:
    #             reverse_connections[connection].append(machine)


    #     for (machine, connection_list) in reverse_connections.items():
    #         connections_to_ips = [ips[connection] for connection in connection_list]
    #         print(f'Machine {machine} is whitelisting {connection_list}')
    #         print(f'IP {ips[machine]} is whitelisting {connections_to_ips}')
    #         data = None
    #         with open(f'machine_{machine}/playbook.yml') as f: 
    #             data = yaml.load(f)
    #         data[0]['vars']['ufw'] = dict()
    #         data[0]['vars']['ufw']['ips'] = connections_to_ips
    #         with open(f'machine_{machine}/playbook.yml', 'w') as f:
    #             yaml.dump(data, f, default_flow_style=False)

    #     for machine in machine_list:
    #         orig = './provision.sh'
    #         target = f'./machine_{machine.machine_number}/provision.sh'
    #         shutil.copyfile(orig, target)
    #         command = None
    #         with open(target) as f:
    #             command = f.readline()

    #         with open(target, 'w') as f:
    #             command = command.replace("{{IP}}", machine.ip)
    #             f.write(command)




    # # if method == 'create':
    # #     with open("connections.txt") as f:
    # #         content = f.read().splitlines()
    # #         for line in content:


    # # if method == 'refresh':
    # #     for machine in machine_list:
    # #         ips[machine.machine_number] = machine.ip
    # # pprint(ips)



    # #     # with open("connections.txt") as f:
    # #     #     content = f.read().splitlines()
    # #     #     for line in content:
    # #     #         machine_num, whitelist = line.split(",")
    # #     #         whitelist = whitelist[1 : len(whitelist) - 1]
    # #     #         print(machine_num, whitelist)