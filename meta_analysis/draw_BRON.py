from typing import List, Any, Dict, Tuple
import os

import numpy as np
import networkx as nx
from matplotlib import pyplot as plt

from meta_analysis.find_riskiest_software import load_graph_network


# TODO get the networkx node type instead of Any
def _get_node_by_category(nodes: List[Any], category: str) -> List[Any]:
    return sorted([_ for _ in nodes if _.startswith(category)])


def _set_position(
    positions: Dict[str, Tuple[float]], start: float, data: List[Any]
) -> None:
    _pos = [(start, _) for _ in np.linspace(0, 0.9, num=len(data))]
    for _i, node in enumerate(data):
        positions[node] = _pos[_i]


def draw_bron(bron_file_path: str, graph_name: str, output_path: str = ".") -> None:
    # Load data
    bron_graph = load_graph_network(bron_file_path)

    # Get the node types
    node_keys = ("tactic", "technique", "capec", "cwe", "cve", "cpe")
    position_starts = np.linspace(0.1, 0.9, num=len(node_keys))
    colors = ("w", "b", "r", "g", "y", "orange")
    nodes = {}
    positions = {}
    label_data = {}
    _, ax = plt.subplots()
    for i, k in enumerate(node_keys):
        # get node category
        nodes[k] = _get_node_by_category(bron_graph.nodes, k)
        # set postions
        _set_position(positions, position_starts[i], nodes[k])
        # draw nodes
        nx.draw_networkx_nodes(
            bron_graph,
            positions,
            nodelist=nodes[k],
            node_color=colors[i],
            alpha=0.5,
            node_shape="s",
        )
        an1 = ax.annotate(
            f"{k}",
            xy=(position_starts[i], 0.99),
            xycoords="data",
            va="center",
            ha="center",
            bbox=dict(boxstyle="round", fc="w"),
        )
        # Get labels
        for node in nodes[k]:
            _str = node.split("_")[1:][0]
            if k == "cpe":
                _str = ":".join(_str.split(":")[3:5])

            label_data[node] = _str

    # draw edges
    nx.draw_networkx_edges(bron_graph, positions, alpha=0.5)
    # draw labels
    nx.draw_networkx_labels(
        bron_graph, positions, label_data, font_size=4, font_type="bold"
    )

    ax.get_xaxis().set_visible(False)
    ax.get_yaxis().set_visible(False)
    ax.set_xlim(0, 1)

    # Save data
    plot_path = os.path.join(output_path, f"bron_plot_{graph_name}.pdf")
    plt.savefig(plot_path)
