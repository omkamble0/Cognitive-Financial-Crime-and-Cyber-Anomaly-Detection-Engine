"""
FinCipher AI — Universal Multi-Hop Graph Analytics Engine
Author: Om Kamble
"""

import time
from collections import deque, defaultdict
from typing import Dict, Any, List, Set, Optional, Tuple
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    type: str
    risk_score: float = 0.0
    attributes: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    weight: float = 1.0
    timestamp: float = Field(default_factory=time.time)


class SubgraphCluster(BaseModel):
    cluster_id: str
    root_entity_id: str
    total_nodes: int
    total_edges: int
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    max_risk_score: float
    is_syndicate: bool
    syndicate_type: Optional[str] = None


class UniversalGraphEngine:
    """
    In-memory graph analytics engine supporting multi-hop entity traversal,
    shared infrastructure detection, and fraud syndicate discovery.
    """

    def __init__(self):
        # Adjacency list: entity_id -> list of (target_id, relationship, weight)
        self._adj: Dict[str, List[Tuple[str, str, float]]] = defaultdict(list)
        # Node metadata: entity_id -> GraphNode
        self._nodes: Dict[str, GraphNode] = {}
        # Undirected edge set for duplicate prevention
        self._edges: Set[Tuple[str, str, str]] = set()

    def add_node(self, entity_id: str, entity_type: str, risk_score: float = 0.0, attributes: Optional[Dict[str, Any]] = None):
        """Registers or updates a node in the graph."""
        if entity_id not in self._nodes:
            self._nodes[entity_id] = GraphNode(
                id=entity_id,
                type=entity_type.upper(),
                risk_score=risk_score,
                attributes=attributes or {}
            )
        else:
            self._nodes[entity_id].risk_score = max(self._nodes[entity_id].risk_score, risk_score)
            if attributes:
                self._nodes[entity_id].attributes.update(attributes)

    def add_edge(
        self,
        source_id: str,
        source_type: str,
        target_id: str,
        target_type: str,
        relationship: str,
        weight: float = 1.0
    ):
        """Adds a bi-directional relationship between two entities."""
        self.add_node(source_id, source_type)
        self.add_node(target_id, target_type)

        edge_key = (min(source_id, target_id), max(source_id, target_id), relationship.upper())
        if edge_key not in self._edges:
            self._edges.add(edge_key)
            self._adj[source_id].append((target_id, relationship.upper(), weight))
            self._adj[target_id].append((source_id, relationship.upper(), weight))

    def find_connected_entities(self, root_id: str, max_hops: int = 2) -> List[str]:
        """BFS multi-hop traversal to find all connected entities within max_hops distance."""
        if root_id not in self._nodes:
            return []

        visited: Set[str] = {root_id}
        queue = deque([(root_id, 0)])

        while queue:
            curr_node, hops = queue.popleft()
            if hops >= max_hops:
                continue

            for neighbor, _, _ in self._adj.get(curr_node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, hops + 1))

        return list(visited)

    def extract_neighborhood_subgraph(self, root_id: str, max_hops: int = 2) -> SubgraphCluster:
        """Extracts complete nodes and edges for visual rendering or forensic case export."""
        connected_ids = set(self.find_connected_entities(root_id, max_hops=max_hops))
        if root_id not in connected_ids:
            connected_ids.add(root_id)

        sub_nodes = [self._nodes[nid] for nid in connected_ids if nid in self._nodes]
        sub_edges = []
        seen_edges = set()

        for nid in connected_ids:
            for neighbor, rel, w in self._adj.get(nid, []):
                if neighbor in connected_ids:
                    edge_tuple = (min(nid, neighbor), max(nid, neighbor), rel)
                    if edge_tuple not in seen_edges:
                        seen_edges.add(edge_tuple)
                        sub_edges.append(GraphEdge(source=nid, target=neighbor, relationship=rel, weight=w))

        max_risk = max([n.risk_score for n in sub_nodes], default=0.0)
        
        # Check if cluster qualifies as a syndicate ring
        user_nodes = [n for n in sub_nodes if n.type == "USER"]
        device_or_ip = [n for n in sub_nodes if n.type in ("DEVICE", "IP_ADDRESS")]
        is_syndicate = len(user_nodes) >= 3 and len(device_or_ip) >= 1
        syndicate_type = "COLLUDING_IDENTITIES_SHARED_INFRASTRUCTURE" if is_syndicate else None

        return SubgraphCluster(
            cluster_id=f"CLUST_{abs(hash(root_id)) % 1000000}",
            root_entity_id=root_id,
            total_nodes=len(sub_nodes),
            total_edges=len(sub_edges),
            nodes=sub_nodes,
            edges=sub_edges,
            max_risk_score=max_risk,
            is_syndicate=is_syndicate,
            syndicate_type=syndicate_type
        )


# Singleton universal graph engine
universal_graph_engine = UniversalGraphEngine()
