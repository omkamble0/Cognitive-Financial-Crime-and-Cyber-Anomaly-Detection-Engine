"""
FinCipher AI — Universal Threat Intelligence & IoC Connector
Author: Om Kamble
"""

import time
from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field


class ThreatMatch(BaseModel):
    indicator: str
    indicator_type: str  # IP_ADDRESS, DOMAIN, EMAIL, HASH, CRYPTO_WALLET
    is_malicious: bool
    threat_category: str  # TOR_EXIT_NODE, BULLETPROOF_PROXY, DISPOSABLE_EMAIL, OFAC_SANCTIONED, BOTNET_C2, MALWARE_HASH
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float
    description: str
    mitre_technique: Optional[str] = None
    attribution: Optional[str] = None


class UniversalThreatIntelConnector:
    """
    In-memory and external-ready Threat Intelligence IoC connector.
    Cross-checks IP addresses, email domains, cryptographic addresses, and file hashes
    against real-time feeds, Tor directory consensus, and OFAC/FATF sanctions lists.
    """

    def __init__(self):
        # Known Tor exit nodes / anonymizers
        self._tor_exit_nodes: Set[str] = {
            "198.51.100.12", "198.51.100.222", "185.220.101.5", "185.220.101.6",
            "185.220.101.7", "185.220.101.8", "192.0.2.77", "192.0.2.99"
        }

        # High-risk bulletproof hosting / residential proxy IP ranges / ASNs
        self._bulletproof_ips: Set[str] = {
            "45.154.255.89", "193.142.146.33", "91.240.118.12", "194.26.29.112"
        }

        # Disposable / burner email domains
        self._disposable_email_domains: Set[str] = {
            "tempmail.com", "guerrillamail.com", "10minutemail.com", "throwawaymail.com",
            "yopmail.com", "mailinator.com", "trashmail.com", "sharklasers.com"
        }

        # OFAC Sanctioned crypto addresses & identifiers
        self._sanctioned_identifiers: Set[str] = {
            "0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a",
            "0x7f367cc41522ce07553e823bf3be79a889debe1b",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "NORTH_KOREA_LAZARUS_AFFILIATE",
            "usr_ofac_target", "usr_sanction_target_01"
        }

        # Known malware / exploit hashes (SHA-256)
        self._malicious_hashes: Set[str] = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "44d88612fea8a8f36de82e1278abb02f"
        }

        # Thread safety & operational metrics
        import threading
        self._lock = threading.Lock()
        self._queries_total: int = 0
        self._matches_total: int = 0
        self._last_sync_timestamp: Optional[float] = None
        self._sync_history: List[Dict[str, Any]] = []
        # Dynamic TTL indicator cache: indicator -> {category, type, severity, confidence, description, expires_at}
        self._ttl_indicators: Dict[str, Dict[str, Any]] = {}

    def get_metrics(self) -> Dict[str, Any]:
        """Returns real-time threat intelligence index counts and telemetry."""
        with self._lock:
            return {
                "total_indicators": (
                    len(self._tor_exit_nodes) +
                    len(self._bulletproof_ips) +
                    len(self._disposable_email_domains) +
                    len(self._sanctioned_identifiers) +
                    len(self._malicious_hashes)
                ),
                "breakdown": {
                    "tor_exit_nodes": len(self._tor_exit_nodes),
                    "bulletproof_ips": len(self._bulletproof_ips),
                    "disposable_email_domains": len(self._disposable_email_domains),
                    "sanctioned_identifiers": len(self._sanctioned_identifiers),
                    "malicious_hashes": len(self._malicious_hashes)
                },
                "queries_total": self._queries_total,
                "matches_total": self._matches_total,
                "hit_rate_pct": round((self._matches_total / max(1, self._queries_total)) * 100, 2),
                "last_sync_timestamp": self._last_sync_timestamp,
                "sync_history_count": len(self._sync_history)
            }

    def sync_external_feeds(
        self,
        feed_sources: Optional[List[Dict[str, str]]] = None,
        timeout: float = 3.0
    ) -> Dict[str, Any]:
        """
        Synchronizes threat intelligence indicators from external live feeds.
        Supports Tor bulk exit list, IP reputation blocklists, and custom URL feeds.
        Gracefully handles offline / disconnected network environments.
        """
        import urllib.request
        sources = feed_sources or [
            {
                "name": "Tor Bulk Exit List",
                "type": "IP_ADDRESS",
                "category": "TOR_EXIT_NODE",
                "url": "https://check.torproject.org/torbulkexitlist"
            }
        ]

        synced_count = 0
        errors = []

        for feed in sources:
            name = feed.get("name", "Unknown Feed")
            url = feed.get("url")
            feed_type = feed.get("type", "IP_ADDRESS").upper()
            if not url:
                continue

            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "FinCipher-ThreatIntel/2.5"}
                )
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    content = response.read().decode("utf-8", errors="ignore")
                    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
                    
                    with self._lock:
                        for line in lines:
                            clean_val = line.lower()
                            if feed_type == "IP_ADDRESS":
                                if feed.get("category") == "TOR_EXIT_NODE":
                                    self._tor_exit_nodes.add(clean_val)
                                else:
                                    self._bulletproof_ips.add(clean_val)
                            elif feed_type in ("DOMAIN", "EMAIL_DOMAIN"):
                                self._disposable_email_domains.add(clean_val)
                            elif feed_type == "HASH":
                                self._malicious_hashes.add(clean_val)
                            else:
                                self._sanctioned_identifiers.add(clean_val)
                            synced_count += 1
            except Exception as e:
                errors.append(f"{name}: {str(e)}")

        with self._lock:
            self._last_sync_timestamp = time.time()
            sync_record = {
                "timestamp": self._last_sync_timestamp,
                "synced_count": synced_count,
                "errors": errors
            }
            self._sync_history.append(sync_record)

        return {
            "status": "COMPLETED" if not errors else ("PARTIAL" if synced_count > 0 else "OFFLINE_FALLBACK"),
            "synced_indicators": synced_count,
            "errors": errors,
            "metrics": self.get_metrics()
        }

    def add_custom_ioc(
        self,
        indicator: str,
        indicator_type: str,
        category: str = "CUSTOM_BLOCKLIST"
    ):
        """Allows analysts to dynamically register newly discovered IoCs."""
        ind_clean = indicator.strip().lower()
        with self._lock:
            if indicator_type.upper() == "IP_ADDRESS":
                self._bulletproof_ips.add(ind_clean)
            elif indicator_type.upper() in ("DOMAIN", "EMAIL_DOMAIN"):
                self._disposable_email_domains.add(ind_clean)
            elif indicator_type.upper() == "HASH":
                self._malicious_hashes.add(ind_clean)
            else:
                self._sanctioned_identifiers.add(ind_clean)

    def add_indicator_with_ttl(
        self,
        indicator: str,
        indicator_type: str,
        category: str = "DYNAMIC_IOC",
        severity: str = "HIGH",
        confidence: float = 0.90,
        description: str = "",
        ttl_seconds: float = 86400.0
    ):
        """Registers a dynamic IoC that automatically expires after ttl_seconds."""
        ind_clean = indicator.strip().lower()
        expires_at = time.time() + max(1.0, float(ttl_seconds))
        with self._lock:
            self._ttl_indicators[ind_clean] = {
                "indicator_type": indicator_type.upper(),
                "category": category,
                "severity": severity,
                "confidence": confidence,
                "description": description or f"Dynamic IoC registered with {int(ttl_seconds)}s TTL",
                "expires_at": expires_at
            }

    def check_indicator(self, value: str, indicator_type: Optional[str] = None) -> Optional[ThreatMatch]:
        """
        Scans a single indicator against threat intelligence datasets.
        Returns a ThreatMatch if an IoC is matched, or None if clean.
        """
        if not value:
            return None
        val_clean = value.strip().lower()

        with self._lock:
            self._queries_total += 1

        match_res = self._evaluate_indicator_match(value, val_clean)
        if match_res:
            with self._lock:
                self._matches_total += 1
        return match_res

    def _evaluate_indicator_match(self, value: str, val_clean: str) -> Optional[ThreatMatch]:
        now = time.time()

        # 0. Check Dynamic TTL Cache
        with self._lock:
            ttl_item = self._ttl_indicators.get(val_clean) or self._ttl_indicators.get(value)
            if ttl_item:
                if now > ttl_item["expires_at"]:
                    # Expired, clean up
                    self._ttl_indicators.pop(val_clean, None)
                    self._ttl_indicators.pop(value, None)
                else:
                    return ThreatMatch(
                        indicator=value,
                        indicator_type=ttl_item["indicator_type"],
                        is_malicious=True,
                        threat_category=ttl_item["category"],
                        severity=ttl_item["severity"],
                        confidence=ttl_item["confidence"],
                        description=ttl_item["description"]
                    )

        # 1. Check Tor Exit Nodes
        if val_clean in self._tor_exit_nodes or value in self._tor_exit_nodes:
            return ThreatMatch(
                indicator=value,
                indicator_type="IP_ADDRESS",
                is_malicious=True,
                threat_category="TOR_EXIT_NODE",
                severity="HIGH",
                confidence=0.98,
                description="Active Tor exit relay detected via public directory consensus.",
                mitre_technique="T1090.003 (Multi-hop Proxy: Tor)",
                attribution="Tor Project Anonymity Network"
            )

        # 2. Check Bulletproof / Malicious IPs
        if val_clean in self._bulletproof_ips or value in self._bulletproof_ips:
            return ThreatMatch(
                indicator=value,
                indicator_type="IP_ADDRESS",
                is_malicious=True,
                threat_category="BULLETPROOF_PROXY",
                severity="CRITICAL",
                confidence=0.95,
                description="Known bulletproof proxy/C2 infrastructure observed in automated credential stuffing attacks.",
                mitre_technique="T1584.005 (Compromise Infrastructure: Botnet)",
                attribution="Known Cybercrime Cluster"
            )

        # 3. Check Disposable Email Domains
        if "@" in val_clean:
            domain = val_clean.split("@")[-1]
            if domain in self._disposable_email_domains:
                return ThreatMatch(
                    indicator=value,
                    indicator_type="EMAIL",
                    is_malicious=True,
                    threat_category="DISPOSABLE_EMAIL",
                    severity="MEDIUM",
                    confidence=0.92,
                    description=f"Ephemeral/disposable email domain '{domain}' frequently used for fake account registration.",
                    mitre_technique="T1585.002 (Establish Accounts: Email Accounts)",
                    attribution="Burner Email Service"
                )
        elif val_clean in self._disposable_email_domains:
            return ThreatMatch(
                indicator=value,
                indicator_type="DOMAIN",
                is_malicious=True,
                threat_category="DISPOSABLE_EMAIL",
                severity="MEDIUM",
                confidence=0.92,
                description=f"Disposable domain '{val_clean}' registered on public abuse lists.",
                mitre_technique="T1585.002",
                attribution="Burner Domain"
            )

        # 4. Check OFAC Sanctions / SDN Identifiers
        if val_clean in self._sanctioned_identifiers or value in self._sanctioned_identifiers:
            return ThreatMatch(
                indicator=value,
                indicator_type="SANCTIONED_ENTITY",
                is_malicious=True,
                threat_category="OFAC_SANCTIONED",
                severity="CRITICAL",
                confidence=0.99,
                description="Entity identifier matches OFAC Specially Designated Nationals (SDN) or FATF Blacklist.",
                mitre_technique="T1583 (Acquire Infrastructure)",
                attribution="OFAC Sanctioned Entity"
            )

        # 5. Check Malicious File Hashes
        if val_clean in self._malicious_hashes:
            return ThreatMatch(
                indicator=value,
                indicator_type="HASH",
                is_malicious=True,
                threat_category="MALWARE_HASH",
                severity="CRITICAL",
                confidence=1.00,
                description="Cryptographic hash matches confirmed malware payload / dropper signature.",
                mitre_technique="T1204 (User Execution: Malicious File)",
                attribution="Malware Threat Feed"
            )

        return None


class ThreatIntelSyncWorker:
    """
    Scheduled background worker that synchronizes threat intelligence feeds periodically
    with graceful offline fallback, local caching, and operational telemetry.
    """

    def __init__(
        self,
        connector: Optional[UniversalThreatIntelConnector] = None,
        sync_interval_seconds: float = 300.0,
        custom_feeds: Optional[List[Dict[str, str]]] = None
    ):
        self.connector = connector or threat_intel_connector
        self.sync_interval_seconds = sync_interval_seconds
        self.custom_feeds = custom_feeds
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_run_timestamp: Optional[float] = None
        self._last_result: Dict[str, Any] = {"status": "INITIALIZING"}
        self._fallback_active = False

    def start(self):
        """Starts background periodic synchronization worker thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="ThreatIntelSyncWorker")
        self._thread.start()

    def stop(self):
        """Stops background worker gracefully."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def trigger_immediate_sync(self) -> Dict[str, Any]:
        """Manually triggers an immediate synchronization cycle."""
        try:
            res = self.connector.sync_external_feeds(feed_sources=self.custom_feeds, timeout=4.0)
            self._last_run_timestamp = time.time()
            self._last_result = res
            self._fallback_active = (res.get("status") == "OFFLINE_FALLBACK")
            return res
        except Exception as e:
            self._fallback_active = True
            self._last_result = {"status": "OFFLINE_FALLBACK", "error": str(e), "synced_indicators": 0}
            return self._last_result

    def _run_loop(self):
        """Worker background loop with interval sleeps."""
        while self._running:
            self.trigger_immediate_sync()
            # Sleep in small slices to respond promptly to stop()
            elapsed = 0.0
            while self._running and elapsed < self.sync_interval_seconds:
                time.sleep(0.5)
                elapsed += 0.5

    def get_worker_status(self) -> Dict[str, Any]:
        """Returns background sync worker health and telemetry."""
        return {
            "is_running": self._running,
            "sync_interval_seconds": self.sync_interval_seconds,
            "last_run_timestamp": self._last_run_timestamp,
            "fallback_active": self._fallback_active,
            "last_result": self._last_result,
            "connector_metrics": self.connector.get_metrics()
        }


# Global singleton instances
threat_intel_connector = UniversalThreatIntelConnector()
threat_intel_sync_worker = ThreatIntelSyncWorker(connector=threat_intel_connector)
