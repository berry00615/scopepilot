"""Record PyPI release hashes and verify the downloaded binary wheels before use."""
import hashlib
import json
import re
import urllib.request
import zipfile
from email.parser import BytesParser
from pathlib import Path

root = Path(__file__).resolve().parents[1]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
locks, inventory = [], []
wheels = sorted((root / '.downloads').glob('*.whl'))
if not wheels:
    raise RuntimeError('No downloaded wheels found; existing lock and inventory were not changed')

# Validate the complete input set before networking or replacing either output.
# A cache containing old/new versions must never generate conflicting pins.
parsed_wheels, seen_names = [], set()
for wheel in wheels:
    with zipfile.ZipFile(wheel) as archive:
        metadata = BytesParser().parsebytes(archive.read(next(n for n in archive.namelist() if n.endswith('.dist-info/METADATA'))))
    name, version = metadata['Name'], metadata['Version']
    if not name or not version:
        raise RuntimeError(f'Wheel has no package name or version: {wheel.name}')
    normalized_name = re.sub(r'[-_.]+', '-', name).lower()
    if normalized_name in seen_names:
        raise RuntimeError(f'Multiple wheels for {name}; use one wheel per package before regenerating the lock')
    seen_names.add(normalized_name)
    parsed_wheels.append((wheel, metadata, name, version))

for wheel, metadata, name, version in parsed_wheels:
    with opener.open(f'https://pypi.org/pypi/{name}/{version}/json', timeout=30) as response:
        release = json.load(response)
    files = [f for f in release['urls'] if f['packagetype'] == 'bdist_wheel']
    official = next(f for f in files if f['filename'] == wheel.name)
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if digest != official['digests']['sha256']:
        raise RuntimeError(f'PyPI hash mismatch: {wheel.name}')
    hashes = sorted({f['digests']['sha256'] for f in files})
    locks.append(f'{name}=={version}' + ''.join(' \\\n    --hash=sha256:' + h for h in hashes))
    if name.lower() == 'pywin32':
        locks[-1] = locks[-1].replace(f'{name}=={version}', f'{name}=={version}; sys_platform == "win32"', 1)
    inventory.append({'name': name, 'version': version, 'source': f'https://pypi.org/project/{name}/{version}/', 'project_urls': release['info'].get('project_urls'), 'license': metadata.get('License-Expression') or metadata.get('License') or 'See upstream metadata', 'download_bytes': wheel.stat().st_size, 'file': wheel.name, 'sha256': digest, 'verification': 'Matches official PyPI release SHA-256; wheel-only download; no dependency setup scripts executed'})
(root / 'requirements.lock').write_text('# Generated from official PyPI release metadata; install with --only-binary=:all: --require-hashes.\n' + '\n'.join(locks) + '\n', encoding='utf-8')
(root / 'docs' / 'python-dependencies.json').write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
print(f'Verified and locked {len(inventory)} packages')
