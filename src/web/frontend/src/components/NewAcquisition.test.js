// The New Acquisition page's commands, against each collector's real options (docs/CLI.md; bug P20)
import { buildCommand } from './NewAcquisition';

const base = { encryption: 'key', remote: false, hosts: [], sshUser: '', destination: '', options: {} };

test('gandalf.sh: its own short options, one host with -h, several with -f', () => {
  expect(buildCommand({ ...base, collector: 'bash', options: { memory: true, accesstimes: true, files: true, livecontainers: true } }).command)
    .toBe('sudo ./src/acquisition/bash/gandalf.sh Key Local -m -a -c -l');
  expect(buildCommand({ ...base, collector: 'bash', remote: true, hosts: ['10.0.0.5'], sshUser: 'analyst', destination: '/evidence' }).command)
    .toBe('sudo ./src/acquisition/bash/gandalf.sh Key Remote -o /evidence -h 10.0.0.5 -u analyst');
  const many = buildCommand({ ...base, collector: 'bash', remote: true, hosts: ['ws-01', 'ws-02'] });
  expect(many.command).toBe('sudo ./src/acquisition/bash/gandalf.sh Key Remote -f hosts.list');
  expect(many.hostsList).toBe('hosts.list');
});

test('gandalf.py: -O -M -A -F -L, remote targets from lists/hosts.list', () => {
  expect(buildCommand({ ...base, collector: 'python', encryption: 'password', destination: '/evidence',
    options: { memory: true, accesstimes: true, files: true, livecontainers: true } }).command)
    .toBe('cd src/acquisition && sudo python3 python/gandalf.py Password Local -O /evidence -M -A -F -L');
  const remote = buildCommand({ ...base, collector: 'python', remote: true, hosts: ['ws-01'] });
  expect(remote.command).toBe('cd src/acquisition && sudo python3 python/gandalf.py Key Remote');
  expect(remote.hostsList).toBe('src/acquisition/lists/hosts.list');
});

test('Invoke-Gandalf.ps1: named parameters, Remote reads lists\\hosts.list', () => {
  expect(buildCommand({ ...base, collector: 'powershell', encryption: 'none', destination: 'D:',
    options: { memory: true, files: true, progress: true, noprompt: true } }).command)
    .toBe('cd src\\acquisition; .\\windows\\Invoke-Gandalf.ps1 -EncryptionObject None -Acquisition Local -OutputDirectory D: -Memory -CollectFiles -ShowProgress -NoPrompt');
  const remote = buildCommand({ ...base, collector: 'powershell', remote: true, hosts: ['ws-01'] });
  expect(remote.command).toBe('cd src\\acquisition; .\\windows\\Invoke-Gandalf.ps1 -EncryptionObject Key -Acquisition Remote');
  expect(remote.hostsList).toBe('src\\acquisition\\lists\\hosts.list');
});

test('nothing it can\'t run: no invented options, no Certificate encryption', () => {
  expect(buildCommand({ ...base, collector: 'bash', options: { registry: true, eventlogs: true } }).command)
    .toBe('sudo ./src/acquisition/bash/gandalf.sh Key Local');
  expect(buildCommand({ ...base, collector: 'bash', encryption: 'certificate' }).command).toBe('');
  expect(buildCommand({ ...base, collector: 'perl' }).command).toBe('');
});
