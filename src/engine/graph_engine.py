"""
AegisFlow AI — Universal Dynamic Graph Topology & Common Point of Purchase (CPP) Engine
Author: Om Kamble

Implements Universal Bipartite Graph Analytics & Terminal Compromise Forensics:
1. Constructs an in-memory Bipartite Network Graph: Cards <-> Merchants <-> IPs <-> Devices.
2. Supports Universal Payment Schemes: RuPay, Amex, Visa, Mastercard, Corporate Fleet, Store Closed Loops, Virtual Tokens.
3. Intercepts Distributed Carding Rings & Probing Syndicates across private company & public datasets.
4. Identifies Common Point of Purchase (CPP) breach sources where cards were skimmed regardless of brand/network.
5. Generates real-time force-directed subgraph payloads for SOC cockpit visualization.
"""

import time
from typing import Dict, Any, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from src.engine.universal_instrument import universal_instrument_classifier


@dataclass
class GraphRiskResult:
    graph_risk_score: float             # 0.0 to 1.0
    is_carding_ring: bool               # High-degree IP/Device testing multiple cards
    is_compromised_merchant_edge: bool  # Connected to known Common Point of Purchase
    suspected_cpp_merchant: Optional[str]
    graph_degree: int                   # Degree of connectivity for this entity
    reason_codes: List[str]
    subgraph_nodes: List[Dict[str, Any]]
    subgraph_links: List[Dict[str, Any]]


class GraphTopologyEngine:
    def __init__(
        self,
        max_edge_retention_sec: float = 86400 * 7,  # 7-day sliding window for graph edges
        max_nodes_in_memory: int = 50000,
        ring_card_threshold: int = 4,              # Unique cards from 1 IP across merchants
        cpp_card_overlap_threshold: int = 3        # Number of breached cards sharing 1 merchant
    ):
        self.max_edge_retention_sec = max_edge_retention_sec
        self.max_nodes_in_memory = max_nodes_in_memory
        self.ring_card_threshold = ring_card_threshold
        self.cpp_card_overlap_threshold = cpp_card_overlap_threshold

        # In-Memory Adjacency Structures
        # card_id -> list of (timestamp, merchant_id, ip_address, amount, is_fraud)
        self.card_edges: Dict[str, deque] = defaultdict(deque)
        # merchant_id -> list of (timestamp, card_id, ip_address, amount, is_fraud)
        self.merchant_edges: Dict[str, deque] = defaultdict(deque)
        # ip_address -> list of (timestamp, card_id, merchant_id, amount)
        self.ip_edges: Dict[str, deque] = defaultdict(deque)

        # Compromised Entity Flags (CPP registry)
        # merchant_id -> {"flagged_at": timestamp, "reason": str, "breached_cards_count": int}
        self.compromised_merchants: Dict[str, Dict[str, Any]] = {}
        # card_id -> {"reported_at": timestamp, "is_confirmed_compromise": bool}
        self.known_compromised_cards: Dict[str, Dict[str, Any]] = {}

    def _prune_expired_edges(self, now: float):
        """Maintains bounded memory by evicting edges older than max_edge_retention_sec."""
        cutoff = now - self.max_edge_retention_sec
        
        # Periodic pruning on IP and Card structures
        if len(self.card_edges) > self.max_nodes_in_memory:
            stale_cards = [cid for cid, edges in self.card_edges.items() if not edges or edges[-1]["time"] < cutoff]
            for cid in stale_cards[:5000]:
                del self.card_edges[cid]

        if len(self.ip_edges) > self.max_nodes_in_memory:
            stale_ips = [ip for ip, edges in self.ip_edges.items() if not edges or edges[-1]["time"] < cutoff]
            for ip in stale_ips[:5000]:
                del self.ip_edges[ip]

    def record_transaction(
        self,
        card_id: str,
        merchant_id: str,
        ip_address: str,
        amount: float,
        timestamp: Optional[float] = None,
        is_fraud: bool = False
    ) -> None:
        """Records a transaction edge in the bipartite network graph."""
        now = timestamp or time.time()
        c_id = str(card_id or "unknown_card")
        m_id = str(merchant_id or "merchant_default")
        ip = str(ip_address or "127.0.0.1")

        self._prune_expired_edges(now)

        entry = {
            "time": now,
            "card_id": c_id,
            "merchant_id": m_id,
            "ip": ip,
            "amount": float(amount),
            "is_fraud": bool(is_fraud)
        }

        self.card_edges[c_id].append(entry)
        self.merchant_edges[m_id].append(entry)
        self.ip_edges[ip].append(entry)

        if is_fraud:
            self.flag_card_compromised(c_id, timestamp=now)

    def flag_card_compromised(self, card_id: str, timestamp: Optional[float] = None) -> None:
        """Flags a card as confirmed compromised and triggers CPP discovery."""
        now = timestamp or time.time()
        self.known_compromised_cards[card_id] = {
            "reported_at": now,
            "is_confirmed_compromise": True
        }
        self._evaluate_common_points_of_purchase(now)

    def _evaluate_common_points_of_purchase(self, now: float) -> None:
        """
        Universal Common Point of Purchase (CPP) Discovery Algorithm:
        Identifies merchant or POS terminals visited by multiple compromised cards prior to fraud report.
        Operates universally across all public schemes, corporate cards, and private datasets.
        """
        if len(self.known_compromised_cards) < self.cpp_card_overlap_threshold:
            return

        merchant_hit_counts: Dict[str, Set[str]] = defaultdict(set)
        for card_id in self.known_compromised_cards.keys():
            edges = self.card_edges.get(card_id, [])
            for edge in edges:
                merchant_hit_counts[edge["merchant_id"]].add(card_id)

        for merchant_id, hit_cards in merchant_hit_counts.items():
            if len(hit_cards) >= self.cpp_card_overlap_threshold:
                self.compromised_merchants[merchant_id] = {
                    "flagged_at": now,
                    "reason": f"COMMON_POINT_OF_PURCHASE: Visited by {len(hit_cards)} confirmed compromised cards",
                    "breached_cards_count": len(hit_cards)
                }

    def evaluate_graph_risk(
        self,
        card_id: str,
        merchant_id: str,
        ip_address: str,
        timestamp: Optional[float] = None
    ) -> GraphRiskResult:
        """
        Evaluates real-time graph risk on an incoming transaction:
        1. Checks for Carding Ring Clusters (IP testing cards across merchants).
        2. Checks for Common Point of Purchase (CPP) proximity.
        """
        now = timestamp or time.time()
        c_id = str(card_id or "unknown_card")
        m_id = str(merchant_id or "merchant_default")
        ip = str(ip_address or "127.0.0.1")

        reason_codes: List[str] = []
        graph_risk = 0.0
        is_ring = False
        is_cpp = False
        suspected_cpp = None

        # 1. Evaluate IP Carding Ring Degree (1-hour window)
        ip_records = [r for r in self.ip_edges.get(ip, []) if now - r["time"] <= 3600]
        unique_cards_on_ip = len(set(r["card_id"] for r in ip_records))
        unique_merchants_on_ip = len(set(r["merchant_id"] for r in ip_records))

        if unique_cards_on_ip >= self.ring_card_threshold:
            is_ring = True
            graph_risk = max(graph_risk, 0.86)
            reason_codes.append(
                f"GRAPH_CARDING_RING_CLUSTER: IP {ip} connected to {unique_cards_on_ip} cards across {unique_merchants_on_ip} merchants"
            )

        # 2. Evaluate Merchant Compromise Proximity (Mastercard CPP)
        if m_id in self.compromised_merchants:
            is_cpp = True
            suspected_cpp = m_id
            cpp_info = self.compromised_merchants[m_id]
            graph_risk = max(graph_risk, 0.76)
            reason_codes.append(
                f"GRAPH_CPP_EXPOSURE: Merchant {m_id} identified as Common Point of Purchase ({cpp_info.get('breached_cards_count', 0)} breached cards)"
            )

        # 3. Card Velocity Traversal
        card_records = [r for r in self.card_edges.get(c_id, []) if now - r["time"] <= 3600]
        unique_ips_on_card = len(set(r["ip"] for r in card_records))
        if unique_ips_on_card >= 3:
            graph_risk = max(graph_risk, 0.80)
            reason_codes.append(
                f"GRAPH_CARD_DIFFUSION: Card {c_id} accessed from {unique_ips_on_card} distinct IPs in 60m"
            )

        # Generate lightweight local subgraph for visualizer
        nodes, links = self._generate_subgraph(c_id, m_id, ip)

        return GraphRiskResult(
            graph_risk_score=round(graph_risk, 3),
            is_carding_ring=is_ring,
            is_compromised_merchant_edge=is_cpp,
            suspected_cpp_merchant=suspected_cpp,
            graph_degree=unique_cards_on_ip + unique_merchants_on_ip,
            reason_codes=reason_codes,
            subgraph_nodes=nodes,
            subgraph_links=links
        )

    def _generate_subgraph(
        self,
        card_id: str,
        merchant_id: str,
        ip: str
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Generates a node-link subgraph payload for real-time visualization."""
        profile = universal_instrument_classifier.classify(card_id)
        nodes = [
            {
                "id": card_id,
                "type": "card",
                "label": profile.masked_identifier,
                "scheme": profile.scheme,
                "brand_name": profile.brand_name,
                "category": profile.category.value,
                "color": profile.accent_color,
                "risk": "flagged" if card_id in self.known_compromised_cards else "normal"
            },
            {"id": merchant_id, "type": "merchant", "label": f"Mcht {merchant_id}", "risk": "cpp" if merchant_id in self.compromised_merchants else "normal"},
            {"id": ip, "type": "ip", "label": f"IP {ip}", "risk": "ring" if len(self.ip_edges.get(ip, [])) >= self.ring_card_threshold else "normal"}
        ]
        links = [
            {"source": card_id, "target": merchant_id, "relationship": "TRANSACTS_AT"},
            {"source": ip, "target": card_id, "relationship": "ORIGINATES_CARD"},
            {"source": ip, "target": merchant_id, "relationship": "HITS_GATEWAY"}
        ]
        return nodes, links

    def get_graph_telemetry(self) -> Dict[str, Any]:
        """Returns macro graph statistics for SecOps dashboard."""
        return {
            "total_card_nodes": len(self.card_edges),
            "total_merchant_nodes": len(self.merchant_edges),
            "total_ip_nodes": len(self.ip_edges),
            "compromised_cpp_merchants_count": len(self.compromised_merchants),
            "compromised_cpp_merchants": list(self.compromised_merchants.keys())[:10],
            "known_breached_cards_count": len(self.known_compromised_cards),
            "graph_engine_status": "ONLINE (Universal Bipartite Multi-Scheme Index)"
        }

    def get_full_topology(self, max_nodes: int = 40) -> Dict[str, Any]:
        """
        Exports the current bipartite network graph topology with node types,
        risk status, degree, and connecting edges for visual rendering.
        """
        nodes_dict = {}
        links_list = []

        # 1. Add compromised cards and CPP merchants first
        for card_id in list(self.known_compromised_cards.keys())[:10]:
            profile = universal_instrument_classifier.classify(card_id)
            nodes_dict[card_id] = {
                "id": card_id,
                "label": profile.masked_identifier,
                "type": "card",
                "scheme": profile.scheme,
                "brand_name": profile.brand_name,
                "category": profile.category.value,
                "color": profile.accent_color,
                "risk": "compromised",
                "degree": len(self.card_edges.get(card_id, []))
            }

        for merch_id, info in list(self.compromised_merchants.items())[:6]:
            nodes_dict[merch_id] = {
                "id": merch_id,
                "label": f"Merchant {merch_id}",
                "type": "merchant",
                "risk": "cpp_breach",
                "details": info.get("reason", "Universal CPP Breach"),
                "degree": len(self.merchant_edges.get(merch_id, []))
            }

        # 2. Add ring botnet IPs
        for ip, edges in self.ip_edges.items():
            unique_cards = len(set(e["card_id"] for e in edges))
            if unique_cards >= self.ring_card_threshold:
                nodes_dict[ip] = {
                    "id": ip,
                    "label": f"IP {ip}",
                    "type": "ip",
                    "risk": "ring_botnet",
                    "degree": len(edges)
                }

        # 3. Fill with normal connected nodes up to max_nodes
        for c_id, edges in list(self.card_edges.items())[:max_nodes]:
            if c_id not in nodes_dict and len(nodes_dict) < max_nodes:
                profile = universal_instrument_classifier.classify(c_id)
                nodes_dict[c_id] = {
                    "id": c_id,
                    "label": profile.masked_identifier,
                    "type": "card",
                    "scheme": profile.scheme,
                    "brand_name": profile.brand_name,
                    "category": profile.category.value,
                    "color": profile.accent_color,
                    "risk": "normal",
                    "degree": len(edges)
                }
            for e in list(edges)[:3]:
                m_id = e["merchant_id"]
                ip_addr = e["ip"]
                if m_id not in nodes_dict and len(nodes_dict) < max_nodes:
                    nodes_dict[m_id] = {
                        "id": m_id,
                        "label": f"Merchant {m_id}",
                        "type": "merchant",
                        "risk": "normal",
                        "degree": len(self.merchant_edges.get(m_id, []))
                    }
                if ip_addr not in nodes_dict and len(nodes_dict) < max_nodes:
                    nodes_dict[ip_addr] = {
                        "id": ip_addr,
                        "label": f"IP {ip_addr}",
                        "type": "ip",
                        "risk": "normal",
                        "degree": len(self.ip_edges.get(ip_addr, []))
                    }

        # 4. Generate links between included nodes
        seen_links = set()
        for c_id, edges in self.card_edges.items():
            if c_id in nodes_dict:
                for e in edges:
                    m_id = e["merchant_id"]
                    ip_addr = e["ip"]
                    if m_id in nodes_dict:
                        pair_cm = (c_id, m_id)
                        if pair_cm not in seen_links:
                            seen_links.add(pair_cm)
                            links_list.append({
                                "source": c_id,
                                "target": m_id,
                                "type": "PURCHASE",
                                "amount": e["amount"],
                                "fraud": e.get("is_fraud", False)
                            })
                    if ip_addr in nodes_dict:
                        pair_ic = (ip_addr, c_id)
                        if pair_ic not in seen_links:
                            seen_links.add(pair_ic)
                            links_list.append({
                                "source": ip_addr,
                                "target": c_id,
                                "type": "AUTH_ORIGIN",
                                "amount": e["amount"],
                                "fraud": e.get("is_fraud", False)
                            })

        # If empty graph, seed default demonstration nodes
        if not nodes_dict:
            self._seed_default_demo_graph()
            return self.get_full_topology(max_nodes=max_nodes)

        return {
            "nodes": list(nodes_dict.values()),
            "links": links_list,
            "telemetry": self.get_graph_telemetry()
        }

    def _seed_default_demo_graph(self):
        """Seeds initial realistic topology with multi-scheme cards and enterprise entities."""
        demo_cards = [
            "card_rupay_6011",
            "card_corp_brex_9021",
            "card_amex_3782",
            "card_fleet_wex_4410",
            "card_store_retail_8820",
            "card_vtoken_dpan_3319",
            "card_visa_4111",
            "card_mc_5200",
            "card_acc_ledger_7712",
            "card_rupay_6521",
            "card_corp_pcard_1044",
            "card_discover_6011"
        ]
        demo_merchants = ["ApexRetail", "CloudServices", "QuickDine", "MetroTransit", "DarkStore_66"]
        demo_ips = ["192.168.1.101", "192.168.1.102", "10.0.0.45", "172.16.8.99", "45.33.32.156"]

        for i, card in enumerate(demo_cards):
            m = demo_merchants[i % len(demo_merchants)]
            ip = demo_ips[i % len(demo_ips)]
            self.record_transaction(card, m, ip, amount=round(float(25.0 + (i * 15.0)), 2), is_fraud=False)

    def simulate_cpp_breach(self) -> Dict[str, Any]:
        """Simulates Universal Common Point of Purchase (CPP) merchant compromise across multiple card schemes."""
        breached_merchant = "DarkStore_66"
        # Diverse card schemes compromised at the same merchant POS terminal
        compromised_cards = [
            "card_breached_rupay_6011",
            "card_breached_corp_fleet_9201",
            "card_breached_amex_3712",
            "card_breached_store_retail_5510",
            "card_breached_visa_4111"
        ]

        # Each compromised card previously shopped at DarkStore_66
        for c in compromised_cards:
            self.record_transaction(c, breached_merchant, "198.51.100.22", amount=49.99, is_fraud=False)
            self.flag_card_compromised(c)

        return self.get_full_topology()

    def simulate_carding_ring(self) -> Dict[str, Any]:
        """Simulates a distributed botnet IP probing multiple stolen cards across schemes."""
        bot_ip = "198.51.100.88"
        target_merchant = "PaymentGateway_Auth"
        probe_cards = [
            "bot_rupay_card_101",
            "bot_corp_card_102",
            "bot_vtoken_card_103",
            "bot_amex_card_104",
            "bot_store_card_105"
        ]
        for probe_card in probe_cards:
            self.record_transaction(probe_card, target_merchant, bot_ip, amount=1.50, is_fraud=True)

        return self.get_full_topology()

    def reset_graph(self) -> Dict[str, Any]:
        """Clears the graph and seeds fresh nominal topology."""
        self.card_edges.clear()
        self.merchant_edges.clear()
        self.ip_edges.clear()
        self.known_compromised_cards.clear()
        self.compromised_merchants.clear()
        self._seed_default_demo_graph()
        return self.get_full_topology()


# Global singleton instance
graph_engine = GraphTopologyEngine()
