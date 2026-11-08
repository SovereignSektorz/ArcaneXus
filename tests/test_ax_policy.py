import importlib.util
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / 'tools' / 'ax_policy.py'
SPEC = importlib.util.spec_from_file_location('ax_policy', MODULE)
ax_policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ax_policy)

class PolicyTests(unittest.TestCase):
    def test_observation_needs_no_approval(self):
        result = ax_policy.classify('github_read_query')
        self.assertEqual(result['level'], 'L0_AUTOMATIC_OBSERVE')
        self.assertEqual(result['approval'], 'NONE')

    def test_reversible_action_requires_a_scope(self):
        result = ax_policy.classify('backup_config')
        self.assertEqual(result['level'], 'L2_SCOPED_REVERSIBLE')
        self.assertEqual(result['approval'], 'PREAUTHORIZED_SCOPE_REQUIRED')

    def test_consequential_action_requires_explicit_approval(self):
        result = ax_policy.classify('delete_file')
        self.assertEqual(result['approval'], 'EXPLICIT_APPROVAL_REQUIRED')

    def test_unknown_action_fails_closed(self):
        result = ax_policy.classify('unknown_future_action')
        self.assertEqual(result['level'], 'REVIEW_REQUIRED')
        self.assertEqual(result['approval'], 'EXPLICIT_REVIEW_REQUIRED')

if __name__ == '__main__':
    unittest.main()
