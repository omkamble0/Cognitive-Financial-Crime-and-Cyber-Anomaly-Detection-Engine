"""
AegisNexus — Universal Event Normalizer & Ingestion Service
Author: Om Kamble
"""

import time
import uuid
from typing import Dict, Any, List, Tuple
from libs.models.events import GenericEvent, DomainType, EventType, EntityLink
from libs.models.entities import Entity, EntityType, Relationship, RelationshipType


class UniversalEventNormalizer:
    """Normalizes domain-specific payloads into standardized GenericEvent objects."""

    @staticmethod
    def normalize_banking_payment(raw: Dict[str, Any]) -> GenericEvent:
        """Adapts banking payment / wire into GenericEvent."""
        tx_id = str(raw.get("transaction_id") or raw.get("id") or f"TX_{uuid.uuid4().hex[:8]}")
        user_id = str(raw.get("user_id") or raw.get("customer_id") or "usr_unknown")
        account_id = str(raw.get("account_id") or raw.get("source_account") or f"acc_{user_id}")
        dest_account = str(raw.get("beneficiary_account") or raw.get("destination_account") or "")
        ip_addr = str(raw.get("ip_address") or "127.0.0.1")
        device_id = str(raw.get("device_id") or raw.get("fingerprint") or f"dev_{user_id}")

        entities = [
            EntityLink(id=user_id, type=EntityType.USER, role="ACTOR"),
            EntityLink(id=account_id, type=EntityType.ACCOUNT, role="SOURCE"),
            EntityLink(id=ip_addr, type=EntityType.IP_ADDRESS, role="NETWORK"),
            EntityLink(id=device_id, type=EntityType.DEVICE, role="ORIGIN")
        ]
        if dest_account:
            entities.append(EntityLink(id=dest_account, type=EntityType.ACCOUNT, role="DESTINATION"))

        return GenericEvent(
            event_id=f"EVT_{tx_id}",
            domain=DomainType.BANKING,
            event_type=EventType.PAYMENT,
            timestamp=float(raw.get("timestamp") or time.time()),
            source=raw.get("source", "core_banking_gateway"),
            primary_entity_id=user_id,
            entities=entities,
            payload={
                "amount": float(raw.get("amount", 0.0)),
                "currency": str(raw.get("currency", "USD")),
                "merchant_id": raw.get("merchant_id"),
                "beneficiary_country": raw.get("beneficiary_country"),
                "channel": raw.get("channel", "ONLINE"),
                "raw_features": {k: v for k, v in raw.items() if k.startswith("v") or k.startswith("V")}
            },
            context={
                "ip_address": ip_addr,
                "device_id": device_id,
                "country": raw.get("country") or raw.get("beneficiary_country"),
                "geo_lat": raw.get("lat"),
                "geo_lon": raw.get("lon"),
                "tenant_id": raw.get("tenant_id", "default")
            },
            tenant_id=raw.get("tenant_id", "default")
        )

    @staticmethod
    def normalize_cyber_auth(raw: Dict[str, Any]) -> GenericEvent:
        """Adapts IT / IAM authentication / syslog / CloudTrail event."""
        event_id = str(raw.get("log_id") or f"LOG_{uuid.uuid4().hex[:8]}")
        user_id = str(raw.get("username") or raw.get("user_id") or "sys_unknown")
        ip_addr = str(raw.get("source_ip") or raw.get("ip_address") or "127.0.0.1")
        asset_id = str(raw.get("target_host") or raw.get("asset_id") or "srv-auth-cluster")
        app_name = str(raw.get("application") or raw.get("service") or "identity-gateway")

        entities = [
            EntityLink(id=user_id, type=EntityType.USER, role="ACTOR"),
            EntityLink(id=ip_addr, type=EntityType.IP_ADDRESS, role="NETWORK"),
            EntityLink(id=asset_id, type=EntityType.ASSET, role="RESOURCE"),
            EntityLink(id=app_name, type=EntityType.APPLICATION, role="TARGET")
        ]

        action = str(raw.get("action", "LOGIN")).upper()
        evt_type = EventType.LOGIN if "LOGIN" in action else (EventType.PRIVILEGE_ESCALATION if "SUDO" in action or "ROLE" in action else EventType.ACCESS_REQUEST)

        return GenericEvent(
            event_id=f"EVT_{event_id}",
            domain=DomainType.CYBERSECURITY,
            event_type=evt_type,
            timestamp=float(raw.get("timestamp") or time.time()),
            source=raw.get("source", "siem_collector"),
            primary_entity_id=user_id,
            entities=entities,
            payload={
                "status": raw.get("status", "SUCCESS"),
                "auth_method": raw.get("auth_method", "PASSWORD"),
                "is_mfa": bool(raw.get("is_mfa", False)),
                "privilege_level": raw.get("privilege_level", "STANDARD"),
                "failure_reason": raw.get("failure_reason")
            },
            context={
                "ip_address": ip_addr,
                "asset_id": asset_id,
                "geo_lat": raw.get("lat"),
                "geo_lon": raw.get("lon"),
                "city": raw.get("city"),
                "country": raw.get("country"),
                "tenant_id": raw.get("tenant_id", "default")
            },
            tenant_id=raw.get("tenant_id", "default")
        )

    @staticmethod
    def normalize_ecommerce_order(raw: Dict[str, Any]) -> GenericEvent:
        """Adapts E-commerce checkout, coupon usage, or refund into GenericEvent."""
        order_id = str(raw.get("order_id") or f"ORD_{uuid.uuid4().hex[:8]}")
        user_id = str(raw.get("customer_id") or raw.get("user_id") or "guest_buyer")
        merchant_id = str(raw.get("seller_id") or raw.get("merchant_id") or "store_main")
        ip_addr = str(raw.get("ip_address") or "127.0.0.1")
        promo_code = raw.get("coupon_code") or raw.get("promo_code")

        entities = [
            EntityLink(id=user_id, type=EntityType.USER, role="ACTOR"),
            EntityLink(id=order_id, type=EntityType.ORDER, role="RESOURCE"),
            EntityLink(id=merchant_id, type=EntityType.MERCHANT, role="DESTINATION"),
            EntityLink(id=ip_addr, type=EntityType.IP_ADDRESS, role="NETWORK")
        ]

        evt_type = EventType.PROMO_APPLIED if promo_code and raw.get("discount_applied") else (EventType.REFUND if raw.get("is_refund") else EventType.ORDER)

        return GenericEvent(
            event_id=f"EVT_{order_id}",
            domain=DomainType.ECOMMERCE,
            event_type=evt_type,
            timestamp=float(raw.get("timestamp") or time.time()),
            source=raw.get("source", "checkout_service"),
            primary_entity_id=user_id,
            entities=entities,
            payload={
                "cart_total": float(raw.get("total_amount", 0.0)),
                "discount_amount": float(raw.get("discount_amount", 0.0)),
                "promo_code": promo_code,
                "items_count": int(raw.get("items_count", 1)),
                "payment_gateway": raw.get("gateway", "STRIPE"),
                "is_guest": bool(raw.get("is_guest", False))
            },
            context={
                "ip_address": ip_addr,
                "shipping_zip": raw.get("shipping_zip"),
                "billing_zip": raw.get("billing_zip"),
                "tenant_id": raw.get("tenant_id", "default")
            },
            tenant_id=raw.get("tenant_id", "default")
        )
