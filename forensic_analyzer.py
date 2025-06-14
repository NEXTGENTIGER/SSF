# forensic_analyzer.py — YARA rules intégrées
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
YARA_INLINE_PATH = '/tmp/yara_inline_rules.yar'

YARA_INLINE_RULES = """
rule Suspicious_Executable {
    meta:
        description = "Détecte les fichiers exécutables suspects"
        severity = "HIGH"
    strings:
        $mz = "MZ"
        $pe = "PE"
        $exe = ".exe"
    condition:
        $mz at 0 and $pe and $exe
}

rule Malicious_Shellcode {
    meta:
        description = "Détecte les shellcodes malveillants"
        severity = "HIGH"
    strings:
        $shellcode1 = { 90 90 90 90 90 90 90 90 }
        $shellcode2 = { 68 ?? ?? ?? ?? C3 }
    condition:
        any of them
}

rule Suspicious_Strings {
    meta:
        description = "Détecte les chaînes de caractères suspectes"
        severity = "MEDIUM"
    strings:
        $cmd = "cmd.exe" nocase
        $powershell = "powershell" nocase
        $wget = "wget" nocase
        $curl = "curl" nocase
        $download = "download" nocase
    condition:
        2 of them
}

rule Suspicious_IP_Address {
    meta:
        description = "Détecte les adresses IP suspectes"
        severity = "MEDIUM"
    strings:
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    condition:
        $ip
}

rule Suspicious_Process {
    meta:
        description = "Détecte les noms de processus suspects"
        severity = "HIGH"
    strings:
        $p1 = "svchost.exe" nocase
        $p2 = "explorer.exe" nocase
        $p3 = "system32" nocase
    condition:
        any of them
}

rule Suspicious_Registry {
    meta:
        description = "Détecte les modifications de registre suspectes"
        severity = "HIGH"
    strings:
        $r1 = "HKEY_LOCAL_MACHINE" nocase
        $r2 = "HKEY_CURRENT_USER" nocase
        $r3 = "RunOnce" nocase
    condition:
        all of them
}

rule Suspicious_Network {
    meta:
        description = "Détecte les activités réseau suspectes"
        severity = "MEDIUM"
    strings:
        $n1 = "http://" nocase
        $n2 = "https://" nocase
        $n3 = "ftp://" nocase
    condition:
        2 of them
}

rule Suspicious_File_Operations {
    meta:
        description = "Détecte les opérations de fichiers suspectes"
        severity = "MEDIUM"
    strings:
        $f1 = "copy" nocase
        $f2 = "move" nocase
        $f3 = "delete" nocase
    condition:
        2 of them
}

rule Suspicious_System_Commands {
    meta:
        description = "Détecte les commandes système suspectes"
        severity = "HIGH"
    strings:
        $c1 = "net user" nocase
        $c2 = "net group" nocase
        $c3 = "net localgroup" nocase
    condition:
        any of them
}

rule Suspicious_Encryption {
    meta:
        description = "Détecte les opérations de chiffrement suspectes"
        severity = "HIGH"
    strings:
        $e1 = "AES" nocase
        $e2 = "RSA" nocase
        $e3 = "encrypt" nocase
    condition:
        2 of them
}
"""

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

def write_inline_yara():
    with open(YARA_INLINE_PATH, 'w') as f:
        f.write(YARA_INLINE_RULES)

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

def get_boot_info():
    return [run_command(name, cmd) for name, cmd in {
        'last_boot': ['who', '-b'],
        'journalctl_boot': ['journalctl', '-b', '--no-pager', '--lines=50'],
        'boot_log': ['dmesg', '--ctime', '--level=err,warn']
    }.items()]

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

def extract_strings(file_path):
    try:
        result = subprocess.run(['strings', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        return [f'Error extracting strings: {e}']

def run_yara_scan(directory):
    results = []
    for file in Path(directory).glob('*'):
        if file.is_file():
            try:
                result = subprocess.run(['yara', YARA_INLINE_PATH, str(file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                results.append({
                    'file': str(file),
                    'matches': result.stdout.strip(),
                    'errors': result.stderr.strip()
                })
            except Exception as e:
                results.append({'file': str(file), 'error': str(e)})
    return results

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

def save_report_json(report, path='forensic_report.json'):
    with open(path, 'w') as f:
        json.dump(report, f, indent=2)
    return path

def upload_to_api(filepath):
    try:
        with open(filepath, 'r') as f:
            response = requests.post(API_ENDPOINT, json=json.load(f), timeout=TIMEOUT)
            print(f"Upload status: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"API upload failed: {e}")

def main():
    write_inline_yara()
    report = []
    report.append({'tool': 'system_analysis', 'results': collect_system_info()})
    report.append({'tool': 'boot_analysis', 'results': get_boot_info()})
    report.append({'tool': 'file_analysis', 'results': analyze_files(SAMPLE_DIR)})
    report.append({'tool': 'strings_extraction', 'results': [
        {'file': str(file), 'strings': extract_strings(str(file))}
        for file in Path(SAMPLE_DIR).glob('*') if file.is_file()
    ]})
    report.append({'tool': 'yara_inline_scan', 'results': run_yara_scan(SAMPLE_DIR)})
    report.append({'tool': 'clamav_scan', 'results': run_clamav_scan(SAMPLE_DIR)})
    report.append({'tool': 'exiftool_metadata', 'results': run_exiftool_scan(SAMPLE_DIR)})
    report.append({'tool': 'binwalk_analysis', 'results': run_binwalk_scan(SAMPLE_DIR)})

    json_path = save_report_json(report)
    upload_to_api(json_path)

if __name__ == '__main__':
    main()
