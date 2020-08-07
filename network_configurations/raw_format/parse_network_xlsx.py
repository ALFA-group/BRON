import argparse
import json
import collections
import os
import ipaddress

import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt


def set_host_ip(ip, host_ip):
    subnet = ip.exploded.split(".")
    subnet[-1] = "0"
    subnet = ".".join(subnet)
    return subnet


def main(network_path, out_path, draw):
    IPS = "Exp IP(s)"
    NX_IPS = "IPs"
    LAN = "LAN"
    NODE_ID = "Node ID"
    ROLE = "Role"
    NET_MASK = "255.255.255.0"
    x1 = pd.read_excel(network_path)
    print(x1.info())

    G = nx.Graph()
    for row in x1.iterrows():
        values = row[1][[NODE_ID, LAN, IPS, ROLE]]
        try:
            ips = [ipaddress.ip_address(_) for _ in values[IPS].split("\n")]
        except AttributeError as e:
            # TODO we assign an IP to firewalls, is that correct
            _df = x1[(x1[LAN] == values[LAN]) & (x1[IPS].notnull())]
            if len(_df) < 2:
                ips = [None]
            else:
                _df = _df[~_df[IPS].str.contains("\n")][IPS]
                _ip = _df.iloc[0]
                _ip = ipaddress.ip_address(_ip)
                _ip = ipaddress.ip_address(set_host_ip(_ip, "0"))
                ips = [_ip]

        key = values[NODE_ID]
        if str(key) == "nan":
            continue
        G.add_node(key)
        G.node[key][NX_IPS] = ips
        G.node[key][LAN] = values[LAN]
        G.node[key][ROLE] = values[ROLE]
        G.node[key][NODE_ID] = values[NODE_ID]

    subnets = []
    # TODO make more efficient...
    for a_node_key in G.nodes:
        a_node = G.node[a_node_key]
        for ip in a_node[NX_IPS]:
            if ip is None:
                continue
            subnet = set_host_ip(ip, "0")
            net = ipaddress.ip_network("{}/{}".format(subnet, NET_MASK))
            subnet = {net: [a_node]}
            for o_node_key in G.nodes:
                if a_node_key == o_node_key:
                    continue
                o_node = G.node[o_node_key]
                for o_ip in o_node[NX_IPS]:
                    if o_ip is None:
                        continue
                    if o_ip in net:
                        subnet[net].append(o_node)

            subnets.append(subnet)

    drawn = set()
    for subnet in subnets:
        for net, nodes in subnet.items():
            if net in drawn:
                continue
            drawn.add(net)
            min_ip = [None, ipaddress.ip_address("255.255.255.255")]
            subnet_nodes = []
            for node in nodes:
                for ip in node[NX_IPS]:
                    if ip in net:
                        subnet_nodes.append(node)
                        if min_ip[1] > ip:
                            min_ip[0] = node
                            min_ip[1] = ip

            for node in subnet_nodes:
                # No self links
                if node[NODE_ID] != min_ip[0][NODE_ID]:
                    G.add_edge(node[NODE_ID], min_ip[0][NODE_ID])

    print(len(drawn), x1[LAN].nunique())
    if draw:
        out_file = "nx_{}.pdf".format(
            os.path.splitext(os.path.basename(network_path))[0]
        )
        draw_network(G, x1, ROLE, os.path.join(out_path, out_file))

    # TODO write JSON encoder instead
    for key in G.nodes:
        node = G.node[key]
        node[NX_IPS] = list(map(str, node[NX_IPS]))

    json_data = nx.readwrite.json_graph.adjacency_data(G)
    network_file_name = "nx_{}.json".format(
        os.path.splitext(os.path.basename(network_path))[0]
    )
    with open(os.path.join(out_path, network_file_name), "w") as f:
        json.dump(json_data, f)


def draw_network(G, x1, ROLE, out_file):
    node_positions = nx.layout.spring_layout(G)

    roles = list(map(str, x1[ROLE].unique()))
    major_roles = collections.defaultdict(int)
    for role in roles:
        major_role = role.split(",")[0]
        major_roles[major_role] += 1

    SHAPES = ["s", "o", "d", ">", "v", "<", "^", "p", "h", "8"]
    shape_map = dict(zip(list(major_roles.keys()), list(range(len(major_roles)))))
    color_map = dict(zip(roles, list(range(len(roles)))))

    for shape in shape_map.keys():
        nodelist = {}
        node_colors = []
        for key in G.nodes:
            node = G.node[key]
            major_role = str(node[ROLE]).split(",")[0]
            if major_role != shape:
                continue
            nodelist[key] = node
            node_colors.append(color_map[str(node[ROLE])])

        nx.draw_networkx_nodes(
            G,
            node_positions,
            nodelist=nodelist.keys(),
            node_size=1,
            width=0.5,
            node_color=node_colors,
            node_shape=shape_map[shape],
        )

    nx.draw_networkx_edges(G, node_positions)

    plt.savefig(out_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse network in xlsx format and save as an adjacency graph in json with networkx"
    )
    parser.add_argument("--draw", action="store_true", help="Draw graph")
    parser.add_argument(
        "--network_path",
        type=str,
        required=True,
        help="Path to network file, e.g network1.xlsx",
    )
    parser.add_argument(
        "--out_path", type=str, required=True, help="Path to output files e.g ."
    )

    args = parser.parse_args()

    main(args.network_path, args.out_path, args.draw)
