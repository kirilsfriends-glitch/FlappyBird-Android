"""Регрессия формата: эталонные контейнеры из docs/test-vectors.json."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import verify_vectors  # noqa: E402


class TestReferenceVectors(unittest.TestCase):
    def test_all_reference_containers_decrypt(self):
        """Если этот тест упал — изменение сломало совместимость формата."""
        self.assertTrue(verify_vectors.run(verbose=False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
