# forensic_toolbook_extended.py
import subprocess
import json
import os
import requests
from pathlib import Path
import magic
import hashlib
import datetime

API_ENDPOINT = 'http://127.0.0.1:5000/api/v1/report/upload_json/'
TIMEOUT = 30
SAMPLE_DIR = '/samples'
YARA_RULES_PATH = '/app/yara_rules.yar'

# SYSTEM COMMANDS
SYSTEM_COMMANDS = {
    'whoami': ['whoami'],
    'hostname': ['hostname'],
    'ip': ['ip', 'a'],
    'netstat': ['netstat', '-tunlp'],
    'ps': ['ps', 'aux'],
    'df': ['df', '-h'],
    'lsblk': ['lsblk'],
    'lsmod': ['lsmod'],
    'uptime': ['uptime']
}

# GENERIC COMMAND EXECUTOR
def run_command(name, cmd):
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return {
            'command': name,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except Exception as e:
        return {'command': name, 'error': str(e)}

def collect_system_info():
    return [run_command(name, cmd) for name, cmd in SYSTEM_COMMANDS.items()]

# BOOT INFO
def get_boot_info():
    boot_cmds = {
        'last_boot': ['who', '-b'],
        'journalctl_boot': ['journalctl', '-b', '--no-pager', '--lines=50'],
        'boot_log': ['dmesg', '--ctime', '--level=err,warn']
    }
    return [run_command(name, cmd) for name, cmd in boot_cmds.items()]

# FILE INFO
def analyze_files(directory):
    results = []
    dir_path = Path(directory)
    if not dir_path.exists():
        return [{'error': f'{directory} not found'}]
    for file in dir_path.glob('*'):
        if file.is_file():
            try:
                results.append({
                    'filename': file.name,
                    'path': str(file.resolve()),
                    'size': file.stat().st_size,
                    'created': datetime.datetime.fromtimestamp(file.stat().st_ctime).isoformat(),
                    'modified': datetime.datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
                    'mime': magic.from_file(str(file), mime=True),
                    'hashes': {
                        'md5': hashlib.md5(file.read_bytes()).hexdigest(),
                        'sha256': hashlib.sha256(file.read_bytes()).hexdigest()
                    }
                })
            except Exception as e:
                results.append({'file': str(file), 'error': str(e)})
    return results

# STRINGS
def extract_strings(file_path):
    try:
        result = subprocess.run(['strings', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        return [f'Error extracting strings: {e}']

# YARA

def run_yara_scan(directory, yara_file):
    results = []
    for file in Path(directory).glob('*'):
        if file.is_file():
            try:
                result = subprocess.run(['yara', yara_file, str(file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                results.append({
                    'file': str(file),
                    'matches': result.stdout.strip(),
                    'errors': result.stderr.strip()
                })
            except Exception as e:
                results.append({'file': str(file), 'error': str(e)})
    return results

# CLAMAV
def run_clamav_scan(directory):
    try:
        result = subprocess.run(['clamscan', '-r', directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return [{
            'tool': 'clamav',
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }]
    except Exception as e:
        return [{'tool': 'clamav', 'error': str(e)}]

# EXIFTOOL
def run_exiftool_scan(directory):
    results = []
    for file in Path(directory).glob('*'):
        if file.is_file():
            try:
                result = subprocess.run(['exiftool', str(file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                results.append({
                    'file': str(file),
                    'metadata': result.stdout.strip()
                })
            except Exception as e:
                results.append({'file': str(file), 'error': str(e)})
    return results

# BINWALK
def run_binwalk_scan(directory):
    results = []
    for file in Path(directory).glob('*'):
        if file.is_file():
            try:
                result = subprocess.run(['binwalk', str(file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                results.append({
                    'file': str(file),
                    'binwalk_output': result.stdout.strip()
                })
            except Exception as e:
                results.append({'file': str(file), 'error': str(e)})
    return results

# EXPORT

def save_report_json(report, path='forensic_report.json'):
    with open(path, 'w') as f:
        json.dump(report, f, indent=2)
    return path

def upload_to_api(filepath):
    with open(filepath, 'r') as f:
        try:
            response = requests.post(API_ENDPOINT, json=json.load(f), timeout=TIMEOUT)
            print(f"Upload status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            print(f"API upload failed: {e}")

# MAIN

def main():
    report = []
    report.append({'tool': 'system_analysis', 'results': collect_system_info()})
    report.append({'tool': 'boot_analysis', 'results': get_boot_info()})
    report.append({'tool': 'file_analysis', 'results': analyze_files(SAMPLE_DIR)})
    report.append({'tool': 'strings_extraction', 'results': [
        {'file': str(file), 'strings': extract_strings(str(file))}
        for file in Path(SAMPLE_DIR).glob('*') if file.is_file()
    ]})
    report.append({'tool': 'yara_scan', 'results': run_yara_scan(SAMPLE_DIR, YARA_RULES_PATH)})
    report.append({'tool': 'clamav_scan', 'results': run_clamav_scan(SAMPLE_DIR)})
    report.append({'tool': 'exiftool_metadata', 'results': run_exiftool_scan(SAMPLE_DIR)})
    report.append({'tool': 'binwalk_analysis', 'results': run_binwalk_scan(SAMPLE_DIR)})

    json_path = save_report_json(report)
    upload_to_api(json_path)

if __name__ == '__main__':
    main()
