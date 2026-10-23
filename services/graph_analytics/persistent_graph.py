"""
FinCipher AI — Persistent Entity Graph & Historical Lineage Analytics Engine
Author: Om Kamble

Architecture:
- Directly backed by enterprise database persistence (PostgreSQL / SQLite):
  * 'entities' table: Stores entity nodes, domain classification, and aggregate risk scores.
  * 'entity_relationships' table: Stores graph edges, connection weights, and observation timestamps.
  * 'generic_events' table: Stores chronological event history for complete behavioral lineage.
- Multi-Hop Graph Traversal: BFS multi-hop expansion surviving process restarts.
- Syndicate Ring Detection: Automatically identifies colluding identity rings and shared infrastructure.
- Entity Historical Lineage: Reconstructs full audit timeline of all transactions and auth attempts.
"""

import time
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import deque
from services.graph_analytics.universal_graph import GraphNode, GraphEdge, SubgraphCluster
from src.db.database import (
    get_entity,
    upsert_entity,
    save_relationship_record,
    get_entity_relationships_db,
    get_entity_events_db,
    get_db_connection,
    IS_POSTGRES
)


class PersistentEntityGraph:
    """
    Database-backed graph engine that provides persistent entity linkage,
    multi-hop neighborhood expansion, and historical event reconstruction.
    """

    def record_node(
        self,
        entity_id: str,
        entity_type: str,
        domain: str = "GENERIC",
        risk_score: float = 0.0,
        attributes: Optional[Dict[str, Any]] = None,
        is_quarantined: bool = False
    ) -> Dict[str, Any]:
        """Persists or updates an entity node in the database."""
        return upsert_entity(
            entity_id=entity_id,
            entity_type=entity_type,
            domain=domain,
            risk_score=risk_score,
            attributes=attributes,
            is_quarantined=is_quarantined
        )

    def record_edge(
        self,
        source_id: str,
        source_type: str,
        target_id: str,
        target_type: str,
        relationship: str,
        weight: float = 1.0,
        attributes: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Persists an edge connecting two entities in the database."""
        # Ensure endpoints exist
        self.record_node(source_id, source_type)
        self.record_node(target_id, target_type)

        return save_relationship_record(
            source_id=source_id,
            source_type=source_type,
            target_id=target_id,
            target_type=target_type,
            rel_type=relationship,
            weight=weight,
            attributes=attributes
        )

    def find_connected_entities(
        self,
        root_id: str,
        max_hops: int = 2,
        max_nodes: int = 60
    ) -> List[str]:
        """
        Executes a database-backed BFS traversal to discover all entities
        connected to root_id within max_hops distance.
        """
        visited: Set[str] = {root_id}
        queue = deque([(root_id, 0)])

        while queue and len(visited) < max_nodes:
            curr_id, hops = queue.popleft()
            if hops >= max_hops:
                continue

            # Query persistent edges from DB
            edges = get_entity_relationships_db(curr_id)
            for e in edges:
                src = e.get("source_entity_id")
                tgt = e.get("target_entity_id")
                neighbor = tgt if src == curr_id else src

                if neighbor and neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, hops + 1))
                    if len(visited) >= max_nodes:
                        break

        return list(visited)

    def extract_neighborhood(
        self,
        root_id: str,
        max_hops: int = 2,
        max_nodes: int = 60
    ) -> SubgraphCluster:
        """
        Constructs a complete SubgraphCluster by pulling nodes and edges
        directly from the persistent database tables.
        """
        connected_ids = self.find_connected_entities(root_id, max_hops=max_hops, max_nodes=max_nodes)
        if root_id not in connected_ids:
            connected_ids.append(root_id)

        # 1. Fetch node metadata from database
        nodes: List[GraphNode] = []
        for nid in connected_ids:
            ent = get_entity(nid)
            if ent:
                nodes.append(GraphNode(
                    id=ent["id"],
                    type=ent.get("type", "UNKNOWN"),
                    domain=ent.get("domain", "GENERIC"),
                    risk_score=float(ent.get("risk_score", 0.0)),
                    attributes=ent.get("attributes", {})
                ))
            else:
                nodes.append(GraphNode(id=nid, type="UNKNOWN", domain="GENERIC", risk_score=0.0))

        # 2. Fetch unique edges between connected nodes
        sub_edges: List[GraphEdge] = []
        seen_edges: Set[Tuple[str, str, str]] = set()

        for nid in connected_ids:
            edges = get_entity_relationships_db(nid)
            for e in edges:
                src = e.get("source_entity_id")
                tgt = e.get("target_entity_id")
                rel = e.get("relationship_type", "RELATED")
                weight = float(e.get("weight", 1.0))

                if src in connected_ids and tgt in connected_ids:
                    pair_key = (min(src, tgt), max(src, tgt), rel)
                    if pair_key not in seen_edges:
                        seen_edges.add(pair_key)
                        sub_edges.append(GraphEdge(
                            source=src,
                            target=tgt,
                            relationship=rel,
                            weight=weight
                        ))

        # 3. Syndicate Ring Detection
        user_nodes = [n for n in nodes if n.type == "USER"]
        infra_nodes = [n for n in nodes if n.type in ("DEVICE", "IP_ADDRESS", "ACCOUNT")]
        is_syndicate = len(user_nodes) >= 3 and len(infra_nodes) >= 1
        syndicate_type = "COLLUDING_IDENTITIES_SHARED_INFRASTRUCTURE" if is_syndicate else None
        max_risk = max([n.risk_score for n in nodes], default=0.0)

        return SubgraphCluster(
            cluster_id=f"PERSIST_CLUST_{abs(hash(root_id)) % 1000000}",
            root_entity_id=root_id,
            total_nodes=len(nodes),
            total_edges=len(sub_edges),
            nodes=nodes,
            edges=sub_edges,
            max_risk_score=max_risk,
            is_syndicate=is_syndicate,
            syndicate_type=syndicate_type
        )

    def get_entity_lineage(self, entity_id: str, limit: int = 50) -> Dict[str, Any]:
        """
        Reconstructs the full historical event lineage for an entity from persistent storage.
        """
        ent = get_entity(entity_id)
        events = get_entity_events_db(entity_id, limit=limit)
        relationships = get_entity_relationships_db(entity_id)

        return {
            "entity_id": entity_id,
            "entity_profile": ent or {"id": entity_id, "status": "UNREGISTERED"},
            "total_historical_events": len(events),
            "historical_events": events,
            "direct_relationships_count": len(relationships),
            "relationships": relationships
        }

    def quarantine_entity(self, entity_id: str, reason: str = "Policy quarantine") -> Dict[str, Any]:
        """Enforces a persistent operational quarantine block on an entity."""
        conn = get_db_connection()
        cursor = conn.cursor()
        param = "%s" if IS_POSTGRES else "?"

        cursor.execute(f"""
            UPDATE entities 
            SET is_quarantined = {param}, risk_score = 0.99, last_seen = CURRENT_TIMESTAMP
            WHERE id = {param}
        """, (1, entity_id))
        conn.commit()
        conn.close()

        return {
            "entity_id": entity_id,
            "status": "QUARANTINED",
            "reason": reason,
            "timestamp": time.time()
        }


# Global singleton persistent entity graph
persistent_entity_graph = PersistentEntityGraph()
