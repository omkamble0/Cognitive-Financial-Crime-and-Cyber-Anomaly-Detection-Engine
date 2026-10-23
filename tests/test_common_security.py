"""
FinCipher AI — Common Utilities & Security Module Unit Tests
Author: Om Kamble
"""

import unittest
from libs.common.utils import current_iso_timestamp, generate_uuid, sha256_hash, calculate_entropy
from libs.common.exceptions import FinCipherException, EntityNotFoundException, PolicyViolationException
from libs.security.tokenization import DataMaskingEngine
from libs.security.rbac import UserRole, Permission, user_has_permission


class TestCommonAndSecurityModules(unittest.TestCase):
    def test_utils_helpers(self):
        # Timestamp
        ts = current_iso_timestamp()
        self.assertTrue(ts.endswith("Z"))

        # UUID
        uid = generate_uuid("evt")
        self.assertTrue(uid.startswith("evt_"))

        # SHA256
        h = sha256_hash({"test": "data", "num": 123})
        self.assertEqual(len(h), 64)

        # Entropy
        ent = calculate_entropy("aaaaaaa")
        self.assertEqual(ent, 0.0)
        ent_rand = calculate_entropy("abcdefghijklmnopqrstuvwxyz1234567890")
        self.assertGreater(ent_rand, 4.0)

    def test_exceptions_hierarchy(self):
        exc = EntityNotFoundException("usr_missing_99")
        self.assertIsInstance(exc, FinCipherException)
        self.assertEqual(exc.code, "ENTITY_NOT_FOUND")

        pol_exc = PolicyViolationException("POL_SANCTIONS", "Entity on OFAC list")
        self.assertEqual(pol_exc.code, "POLICY_VIOLATION")

    def test_data_masking_engine(self):
        # Credit Card PAN masking
        masked_pan = DataMaskingEngine.mask_card_pan("4111111111111234")
        self.assertEqual(masked_pan, "411111******1234")

        # Email masking
        masked_email = DataMaskingEngine.mask_email("alexander.smith@bankcorp.com")
        self.assertTrue(masked_email.startswith("a"))
        self.assertTrue(masked_email.endswith("@bankcorp.com"))
        self.assertIn("*", masked_email)

        # Tokenization
        token1 = DataMaskingEngine.tokenize_identifier("SSN_987-65-4321")
        token2 = DataMaskingEngine.tokenize_identifier("SSN_987-65-4321")
        token3 = DataMaskingEngine.tokenize_identifier("SSN_123-45-6789")
        self.assertEqual(token1, token2)
        self.assertNotEqual(token1, token3)

    def test_rbac_permissions(self):
        # ADMIN has all permissions
        self.assertTrue(user_has_permission(UserRole.ADMIN, Permission.MANAGE_POLICIES))
        self.assertTrue(user_has_permission(UserRole.ADMIN, Permission.OVERRIDE_POLICIES))

        # SENIOR_ANALYST can triage and export, but cannot manage users
        self.assertTrue(user_has_permission(UserRole.SENIOR_ANALYST, Permission.TRIAGE_ALERTS))
        self.assertTrue(user_has_permission(UserRole.SENIOR_ANALYST, Permission.EXPORT_EVIDENCE))
        self.assertFalse(user_has_permission(UserRole.SENIOR_ANALYST, Permission.MANAGE_USERS))

        # READONLY can only read
        self.assertTrue(user_has_permission(UserRole.READONLY, Permission.READ_EVENTS))
        self.assertFalse(user_has_permission(UserRole.READONLY, Permission.TRIAGE_ALERTS))


if __name__ == "__main__":
    unittest.main()
