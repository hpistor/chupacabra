import argparse
import os
from DiGraph import DiGraph

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'A tool to generate networked cyber ranges')
    parser.add_argument("--nodes", default=3, type=int, help="How many different nodes exist in each range")
    parser.add_argument("--times", default=10, type=int, help="How many different adjacency matrices to generate (roughly how many sets of machines to generate)")
    args = parser.parse_args()
    digraph = DiGraph(nodes = args.nodes, times=args.times)
    digraph.create()
    input_str = digraph.get_alpaca_input()
    inputs = input_str.split(' ', 1)
    num_nodes = inputs[0]
    connection_list = inputs[1]

    print(f"Creating {args.nodes} ranges")
    cmd = f"swipl prolog/main.pl createMachineRanges {num_nodes} {connection_list}"
    os.system(cmd) 
