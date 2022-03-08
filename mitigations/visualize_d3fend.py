import os

import rdflib
from rdflib.extras.external_graph_libs import rdflib_to_networkx_multidigraph
import networkx as nx
import matplotlib.pyplot as plt

from mitigations.d3fend_mitigations import D3FEND_ONTOLOGY_TTL, OUT_DIR


def main():
    g = rdflib.Graph()
    result = g.parse(D3FEND_ONTOLOGY_TTL, format="turtle")
    G = rdflib_to_networkx_multidigraph(result)
    # Plot Networkx instance of RDF Graph
    pos = nx.spring_layout(G, scale=2)
    edge_labels = nx.get_edge_attributes(G, "r")
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
    nx.draw(G, with_labels=True)
    # if not in interactive mode for
    plt.savefig(os.path.join(OUT_DIR, "d3fend_viz.pdf"))


if __name__ == "__main__":
    main()
