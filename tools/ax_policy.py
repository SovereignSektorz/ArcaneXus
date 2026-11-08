#!/usr/bin/env python3
"""Read-only ArcaneXus action-risk classifier. It does not authorize or execute."""
import argparse
import json

POLICY = {
    'L0_AUTOMATIC_OBSERVE': {
        'approval': 'NONE',
        'actions': ['workspace_inventory', 'loopback_port_check', 'github_read_query', 'rclone_listremotes'],
        'description': 'Bounded read-only observation; no remote file reads or writes.',
    },
    'L1_AUTOMATIC_ANALYZE': {
        'approval': 'NONE',
        'actions': ['syntax_check', 'unit_test', 'diff_review', 'evidence_report'],
        'description': 'Local analysis and tests; must not mutate protected runtime state.',
    },
    'L2_SCOPED_REVERSIBLE': {
        'approval': 'PREAUTHORIZED_SCOPE_REQUIRED',
        'actions': ['timestamped_report_write', 'backup_config', 'create_feature_branch'],
        'description': 'Only within a narrow, recorded resource/operation/time scope; no scope registry is active yet.',
    },
    'L3_EXPLICIT_APPROVAL': {
        'approval': 'EXPLICIT_APPROVAL_REQUIRED',
        'actions': ['edit_file', 'delete_file', 'sync_remote', 'merge_pr', 'deploy', 'change_permissions', 'publish_release', 'spend_funds', 'expose_network_service', 'execute_device_command'],
        'description': 'Consequential or externally visible operations.',
    },
}

def classify(action):
    for level, rule in POLICY.items():
        if action in rule['actions']:
            return {'action': action, 'level': level, 'approval': rule['approval'], 'description': rule['description'], 'classification_only': True}
    return {'action': action, 'level': 'REVIEW_REQUIRED', 'approval': 'EXPLICIT_REVIEW_REQUIRED', 'description': 'Unknown actions fail closed; no execution is authorized.', 'classification_only': True}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['list', 'check'], nargs='?', default='list')
    parser.add_argument('action', nargs='?')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    if args.command == 'check' and not args.action:
        parser.error('check requires an action name')
    result = classify(args.action) if args.command == 'check' else POLICY
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.command == 'check':
        print(f"{result['action']}: {result['level']} / {result['approval']}")
        print(result['description'])
        print('Classification only. No action was authorized or executed.')
    else:
        for level, rule in POLICY.items():
            print(f"{level} | {rule['approval']}")
            print('  ' + rule['description'])
            print('  ' + ', '.join(rule['actions']))
        print('Unknown actions: REVIEW_REQUIRED. This is not an execution engine.')

if __name__ == '__main__':
    main()
