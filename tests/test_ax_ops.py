import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / 'tools' / 'ax_ops.py'
SPEC = importlib.util.spec_from_file_location('ax_ops', MODULE)
ax_ops = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ax_ops)

class WorkspaceInventoryTests(unittest.TestCase):
    def test_reports_spec_and_backup_named_candidate_without_claiming_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '00_Void').mkdir()
            (root / '00_Void' / 'UNIFIED_REALITY_SPEC.md').write_text('# Spec')
            (root / 'module.py.bak_1').write_text('backup')
            (root / '.git').mkdir()
            report = ax_ops.workspace_inventory(root)
            self.assertEqual(report['state'], 'PRESENT')
            self.assertTrue(report['master_spec_present'])
            self.assertTrue(report['git_checkout'])
            self.assertEqual(report['backup_named_candidates'], ['module.py.bak_1'])
            self.assertIn('Name-based candidates only', report['note'])

    def test_missing_workspace_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / 'missing'
            self.assertEqual(ax_ops.workspace_inventory(missing)['state'], 'NOT_FOUND')

    def test_render_keeps_read_only_boundary_explicit(self):
        report = {
            'controller': 'ArcaneXus Operations Controller',
            'generated_at': '2026-01-01T00:00:00+00:00',
            'execution_mode': 'READ_ONLY',
            'workspace': {'state': 'PRESENT', 'path': '/tmp', 'git_checkout': False,
                          'master_spec_present': True, 'top_level_entries': 1,
                          'backup_named_candidates': []},
            'loopback_services': {'1121': 'NOT_REACHABLE'},
            'rclone': {'state': 'AVAILABLE', 'remote_names': ['gdrive']},
            'github': {'state': 'READ_ONLY_QUERY', 'repos': []},
        }
        output = ax_ops.render(report)
        self.assertIn('Read-only checks only', output)
        self.assertEqual(ax_ops.ACTION_POLICY['L3_EXPLICIT_APPROVAL']['approval'], 'EXPLICIT_APPROVAL_REQUIRED')
        self.assertIn('127.0.0.1:1121: NOT_REACHABLE', output)

if __name__ == '__main__':
    unittest.main()
