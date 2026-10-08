"""Read-only accounting of task-owned files and conservative system-drive growth."""
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
baseline = {'C': {'used': 164542271488, 'free': 51739443200},
            'D': {'used': 605576155136, 'free': 170369032192}}
folders = {}
for path in root.rglob('*'):
    if path.is_file() and not path.is_symlink():
        part = path.relative_to(root).parts[0]
        folders[part] = folders.get(part, 0) + path.stat().st_size
drives = {}
if os.name == 'nt':
    for name, before in baseline.items():
        usage = shutil.disk_usage(name + ':\\')
        drives[name] = {'baseline': before, 'current_used': usage.used, 'current_free': usage.free,
                        'used_change': usage.used - before['used']}
size = sum(folders.values())
# All project files are counted once. C: growth is an intentionally conservative
# allowance; other desktop activity may contribute, so it is not an attribution.
allowance = max(0, drives.get('C', {}).get('used_change', 0))
result = {'measured_at': datetime.now(timezone.utc).isoformat(), 'directory_bytes': folders,
          'project_logical_bytes': size, 'system_drive_growth_allowance': allowance,
          'conservative_accounted_bytes': size + allowance, 'drives': drives,
          'containers_or_vhds_created': False,
          'note': 'Logical bytes may differ from allocated/compressed disk bytes. No unrelated directories were scanned. C: concurrent growth is included conservatively, not attributed wholly to this task.'}
(root / 'docs' / 'disk-usage.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
print(json.dumps({key: result[key] for key in ('project_logical_bytes','system_drive_growth_allowance','conservative_accounted_bytes')}))
if size + allowance >= 40 * 1000**3:
    raise SystemExit('Stop new downloads and large builds: conservative accounting reached 40 GB')
