"""Adversarial tests with independent simulated GitHub authority, no network."""
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import stat
import warnings
import tarfile
import tempfile
import unittest
import zipfile
from scripts.ci import verify_candidate as v

CHECKS=('rust','auth-ingress','ssh-policy','persistence','mqtt','lifecycle','ui','distro-containers','static-amd64','static-arm64','addon-schema','codeql','secrets','cargo-audit','image-scan-amd64','image-scan-arm64','sonar','docs','workflow-lint','commits')
JOB_NAMES = {name: 'tests / ' + name for name in CHECKS}
JOB_NAMES.update(codeql='codeql / codeql', sonar='sonar / Sonar Cloud',
                 commits='commits / Conventional Commits')
SHA='a'*40
REPO='Ryther/ha-wolf-manager'
PREFIX='/repos/'+REPO

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def digest(data):return hashlib.sha256(data).hexdigest()
def elf(machine):
    header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF'+bytes([2,1,1])+bytes(9),2,machine,1,0,64,0,0,64,56,1,0,0,0)
    segment=struct.pack('<IIQQQQQQ',1,5,120,0,0,4,4,4096)
    return header+segment+b'\x00'*4

def archive(entries):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w:gz') as tar:
        for name,data,kind in entries:
            info=tarfile.TarInfo(name);info.mode=0o755 if name.endswith('wolf-manager-host') or name=='install.sh' else (0o444 if name in v.HOST_LICENSES else 0o644)
            if kind=='link':info.type=tarfile.SYMTYPE;info.linkname='/etc/passwd'
            elif kind=='hardlink':info.type=tarfile.LNKTYPE;info.linkname='bin/wolf-manager-host'
            elif kind=='device':info.type=tarfile.CHRTYPE
            else:info.size=len(data)
            tar.addfile(info,io.BytesIO(data) if info.isfile() else None)
    return out.getvalue()

class Authority:
    def __init__(self, run, jobs, artifact):self.run=run;self.jobs=jobs;self.artifact=artifact;self.calls=[]
    def get_json(self,path):
        self.calls.append(path)
        if path==PREFIX+'/actions/runs/99':return copy.deepcopy(self.run)
        if path==PREFIX+'/actions/workflows/77':return {'id':77,'path':'.github/workflows/ci.yaml','state':'active'}
        if path.startswith(PREFIX+'/actions/runs/99/attempts/1/jobs?'):return {'total_count':len(self.jobs),'jobs':copy.deepcopy(self.jobs)}
        if path==PREFIX+'/actions/artifacts/42':return copy.deepcopy(self.artifact)
        if path.startswith(PREFIX+'/actions/runs/99/artifacts?'):return {'total_count':1,'artifacts':[copy.deepcopy(self.artifact)]}
        raise AssertionError('Unexpected independent API path '+path)

def fixture():
    files={
        'wolf-manager-host-v0.1.0-x86_64-unknown-linux-musl.tar.gz':archive([('bin/wolf-manager-host',elf(62),'file'), ('licenses/HA-Wolf-Manager.txt',b'Synthetic MIT\n','file'), ('licenses/rumqttc.txt',b'Synthetic Apache-2.0\n','file')]),
        'wolf-manager-host-v0.1.0-aarch64-unknown-linux-musl.tar.gz':archive([('bin/wolf-manager-host',elf(183),'file'), ('licenses/HA-Wolf-Manager.txt',b'Synthetic MIT\n','file'), ('licenses/rumqttc.txt',b'Synthetic Apache-2.0\n','file')]),
        'ha-wolf-manager-installer-v0.1.0.tar.gz':archive([('install.sh',b'#!/bin/sh\nexit 0\n','file'),('installer/templates/policy.json',b'{}','file')]),
    }
    files['SHA256SUMS']=''.join(digest(data)+'  '+name+'\n' for name,data in sorted(files.items())).encode()
    blobs={}
    def blob(data,media_type):
        data=encoded(data) if isinstance(data,dict) else data
        sha=digest(data);blobs['oci/blobs/sha256/'+sha]=data
        return {'mediaType':media_type,'digest':'sha256:'+sha,'size':len(data)}
    platforms=[]
    for architecture in ('amd64','arm64'):
        config=blob({'architecture':architecture,'os':'linux','config':{'Entrypoint':['/ha-wolf-manager']}},'application/vnd.oci.image.config.v1+json')
        layer=blob(b'fixture layer '+architecture.encode(),'application/vnd.oci.image.layer.v1.tar')
        manifest=blob({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':config,'layers':[layer]},'application/vnd.oci.image.manifest.v1+json')
        manifest['platform']={'os':'linux','architecture':architecture};platforms.append(manifest)
    index=blob({'schemaVersion':2,'mediaType':'application/vnd.oci.image.index.v1+json','manifests':platforms},'application/vnd.oci.image.index.v1+json')
    files.update(blobs)
    for name in CHECKS:files['evidence/'+name+'.json']=encoded({'name':name,'candidate_sha':SHA,'result':'success'})
    files['oci/index.json']=encoded({'schemaVersion':2,'manifests':[index]});files['oci/oci-layout']=encoded({'imageLayoutVersion':'1.0.0'})
    expected=v.Expectations(REPO,SHA,'0.1.0',99,77,'.github/workflows/ci.yaml')
    run={'id':99,'workflow_id':77,'head_sha':SHA,'head_branch':'main','path':'.github/workflows/ci.yaml@main','event':'push','status':'completed','conclusion':'success','run_attempt':1,'repository':{'id':1,'full_name':REPO,'fork':False},'head_repository':{'id':1,'full_name':REPO,'fork':False},'pull_requests':[]}
    jobs=[{'id':i+1,'run_id':99,'head_sha':SHA,'name':JOB_NAMES[name],'status':'completed','conclusion':'success','run_attempt':1} for i,name in enumerate(CHECKS)]
    receipt={'schema_version':1,'candidate_sha':SHA,'version':'0.1.0','workflow_run_id':99,'source_repository':REPO,'target_triples':['x86_64-unknown-linux-musl','aarch64-unknown-linux-musl'],'checks':[{'name':name,'result':'success','candidate_sha':SHA,'scope':'candidate '+name,'evidence_location':'artifact:42/evidence/'+name+'.json'} for name in CHECKS], 'assets':[], 'image':{'repository':'ghcr.io/ryther/ha-wolf-manager','tag':'0.1.0','index_digest':index['digest'],'platforms':[{'os':'linux','architecture':d['platform']['architecture'],'digest':d['digest']} for d in platforms]},'addon':{'slug':'ha_wolf_manager','version':'0.1.0','image_reference':'ghcr.io/ryther/ha-wolf-manager:0.1.0'},'publication_state':'draft'}
    return files,expected,run,jobs,receipt

class CandidateTests(unittest.TestCase):
    def test_host_licenses_are_required_regular_readonly_and_closed(self):
        licenses = [('licenses/HA-Wolf-Manager.txt', b'Synthetic MIT\n', 'file'),
                    ('licenses/rumqttc.txt', b'Synthetic Apache-2.0\n', 'file')]
        content = archive([('bin/wolf-manager-host', elf(62), 'file'), *licenses])
        v.inspect_tar(content, 62)
        for mutation in ('missing', 'unknown', 'link', 'hardlink', 'executable', 'writable'):
            with self.subTest(mutation=mutation):
                entries = [('bin/wolf-manager-host', elf(62), 'file'), *licenses]
                if mutation == 'missing': entries.pop()
                elif mutation == 'unknown': entries.append(('licenses/unknown.txt', b'unknown', 'file'))
                elif mutation in ('link', 'hardlink'):
                    entries[-1] = ('licenses/rumqttc.txt', b'', mutation)
                content = archive(entries)
                if mutation in ('executable', 'writable'):
                    out = io.BytesIO()
                    with tarfile.open(fileobj=io.BytesIO(content)) as original, tarfile.open(fileobj=out, mode='w:gz') as changed:
                        for entry in original:
                            if entry.name == 'licenses/rumqttc.txt': entry.mode = 0o555 if mutation == 'executable' else 0o644
                            changed.addfile(entry, original.extractfile(entry))
                    content = out.getvalue()
                with self.assertRaises(v.VerificationError): v.inspect_tar(content, 62)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.files,self.expected,self.run,self.jobs,self.receipt=fixture()
    def package(self,extra=None):
        self.files['SHA256SUMS']=''.join(digest(data)+'  '+name+'\n' for name,data in sorted(self.files.items()) if name.endswith('.tar.gz')).encode()
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for name,data in self.files.items():z.writestr(name,data)
            if extra:
                for name,data in extra:
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore',UserWarning);z.writestr(name,data)
        data=out.getvalue();file=Path(self.temp.name)/'42.zip';file.write_bytes(data)
        self.receipt['assets']=[{'name':name,'download_url':'https://api.github.com'+PREFIX+'/actions/artifacts/42/zip','sha256':digest(self.files[name]),'size_bytes':len(self.files[name]),'workflow_artifact_id':42,'workflow_artifact_sha256':digest(data)} for name in self.files if name.endswith('.tar.gz') or name=='SHA256SUMS']
        self.authority=Authority(self.run,self.jobs,{'id':42,'name':'release-candidate-'+SHA,'expired':False,'digest':'sha256:'+digest(data),'size_in_bytes':len(data),'workflow_run':{'id':99,'head_sha':SHA,'head_branch':'main','repository_id':1,'head_repository_id':1}})
        return {42:file}
    def verify(self,artifacts=None,raw=None):return v.verify_candidate(raw or encoded(self.receipt),artifacts or self.package(),self.authority,self.expected)
    def rejected(self,change):
        artifacts=self.package();change()
        with self.assertRaises(v.VerificationError):self.verify(artifacts)
    def test_accepts_exact_candidate_with_independent_success_and_preserved_bytes(self):
        artifacts=self.package();raw=encoded(self.receipt);result=self.verify(artifacts,raw)
        self.assertIsInstance(result,dict);self.assertEqual(result['receipt_sha256'],digest(raw));self.assertEqual(result['candidate_sha'],SHA)
        self.assertIn(PREFIX+'/actions/runs/99',self.authority.calls);self.assertIn(PREFIX+'/actions/artifacts/42',self.authority.calls)
    def test_closed_ci_map_accepts_exact_reusable_jobs_and_new_semantic_boundaries(self):
        artifacts = self.package()
        result = self.verify(artifacts)
        self.assertEqual(result['candidate_sha'], SHA)
        self.assertTrue({'docs', 'workflow-lint', 'commits'} <= {c['name'] for c in self.receipt['checks']})

    def test_old_producer_workflow_is_not_an_authorized_expectation(self):
        expected = v.Expectations(REPO, SHA, '0.1.0', 99, 77, '.github/workflows/candidate.yaml')
        with self.assertRaises(v.VerificationError):
            expected.validate()

    def test_refuses_unknown_caller_and_extra_semantic_job_alias(self):
        for mutation in ('wrong-prefix', 'leaf-alias', 'extra-prefix-alias', 'extra-display-alias'):
            with self.subTest(mutation=mutation):
                self.setUp()
                def change():
                    if mutation == 'wrong-prefix':
                        self.authority.jobs[0]['name'] = 'untrusted / rust'
                    else:
                        extra = copy.deepcopy(self.authority.jobs[0])
                        extra['id'] = 1001
                        extra['name'] = {'leaf-alias': 'rust', 'extra-prefix-alias': 'other / rust',
                                         'extra-display-alias': 'other / Conventional Commits'}[mutation]
                        self.authority.jobs.append(extra)
                self.rejected(change)

    def test_all_required_jobs_must_belong_to_current_run_attempt(self):
        for invalid in (2, True, 1.0, '1'):
            with self.subTest(attempt=invalid):
                self.setUp()
                self.rejected(lambda: self.authority.jobs[0].update(run_attempt=invalid))
        self.setUp()
        self.rejected(lambda: self.authority.jobs[0].pop('run_attempt'))

    def test_completed_run_and_new_required_checks_cannot_be_borrowed(self):
        for status, conclusion in [('in_progress', None), ('completed', 'failure'),
                                   ('completed', 'cancelled'), ('completed', 'skipped')]:
            with self.subTest(status=status, conclusion=conclusion):
                self.setUp()
                self.rejected(lambda: self.authority.run.update(status=status, conclusion=conclusion))
        for semantic in ('docs', 'workflow-lint', 'commits'):
            with self.subTest(semantic=semantic):
                self.setUp()
                self.rejected(lambda: self.authority.jobs.__setitem__(slice(None),
                    [j for j in self.authority.jobs if j['name'] != JOB_NAMES[semantic]]))

    def test_attempt_change_while_collecting_jobs_refuses_stale_success(self):
        artifacts = self.package()
        original = self.authority.get_json
        calls = 0
        def changing(path):
            nonlocal calls
            data = original(path)
            if path == PREFIX + '/actions/runs/99':
                calls += 1
                if calls > 1:
                    data = copy.deepcopy(data)
                    data['run_attempt'] = 2
                    data['status'] = 'in_progress'
                    data['conclusion'] = None
            return data
        self.authority.get_json = changing
        with self.assertRaisesRegex(v.VerificationError, 'changing_run_evidence'):
            self.verify(artifacts)

    def test_receipt_success_cannot_override_independent_failed_job(self):self.rejected(lambda:self.authority.jobs[0].update(conclusion='failure'))
    def test_refuses_missing_duplicate_and_suffix_ambiguous_job_names(self):
        for mutation in ('missing','duplicate','suffix'):
            with self.subTest(mutation=mutation):
                self.setUp()
                def change():
                    if mutation=='missing':self.authority.jobs.pop()
                    elif mutation=='duplicate':self.authority.jobs.append(copy.deepcopy(self.authority.jobs[0]))
                    else:self.authority.jobs[0]['name']='rust (ubuntu)'
                self.rejected(change)
    def test_refuses_pr_fork_wrong_workflow_path_and_other_candidate_sha(self):
        for field,value in [('event','pull_request'),('head_sha','b'*40),('workflow_id',88),('path','.github/workflows/untrusted.yaml@main'),('head_branch','feature')]:
            with self.subTest(field=field):self.setUp();self.rejected(lambda:self.authority.run.update({field:value}))
        self.setUp();self.rejected(lambda:self.authority.run['head_repository'].update(fork=True))
    def test_refuses_receipt_identity_and_missing_or_duplicate_check_claims(self):
        for field,value in [('schema_version',2),('candidate_sha','b'*40),('version','0.2.0'),('workflow_run_id',100),('source_repository','attacker/fork')]:
            with self.subTest(field=field):self.setUp();self.rejected(lambda:self.receipt.update({field:value}))
        self.setUp();self.rejected(lambda:self.receipt['checks'].pop())
        self.setUp();self.rejected(lambda:self.receipt['checks'].append(copy.deepcopy(self.receipt['checks'][0])))
    def test_refuses_asset_checksum_size_or_api_artifact_digest_mismatch(self):
        for mutation in ('checksum','size','api_digest','expired','artifact_run'):
            with self.subTest(mutation=mutation):
                self.setUp()
                def change():
                    if mutation=='checksum':self.receipt['assets'][0]['sha256']='f'*64
                    elif mutation=='size':self.receipt['assets'][0]['size_bytes']+=1
                    elif mutation=='api_digest':self.authority.artifact['digest']='sha256:'+'f'*64
                    elif mutation=='expired':self.authority.artifact['expired']=True
                    else:self.authority.artifact['workflow_run']['id']=100
                self.rejected(change)
    def test_refuses_zip_traversal_absolute_duplicates_and_symlink_without_extraction(self):
        for name in ('../escape','/absolute','oci/../escape','oci/index.json'):
            with self.subTest(name=name):
                self.setUp();artifacts=self.package([(name,b'bad')])
                with self.assertRaises(v.VerificationError):self.verify(artifacts)
                self.assertFalse((Path(self.temp.name)/'escape').exists())
    def test_refuses_tar_traversal_links_devices_and_duplicate_entries(self):
        for name,kind in [('../escape','file'),('/absolute','file'),('bin/link','link'),('bin/hard','hardlink'),('bin/device','device'),('bin/wolf-manager-host','file')]:
            with self.subTest(name=name,kind=kind):
                self.setUp();key='wolf-manager-host-v0.1.0-x86_64-unknown-linux-musl.tar.gz';self.files[key]=archive([('bin/wolf-manager-host',elf(62),'file'),(name,b'bad',kind)]);artifacts=self.package()
                with self.assertRaises(v.VerificationError):self.verify(artifacts)
    def test_refuses_wrong_binary_architecture_or_missing_platform_and_addon_identity(self):
        self.files['wolf-manager-host-v0.1.0-x86_64-unknown-linux-musl.tar.gz']=archive([('bin/wolf-manager-host',elf(183),'file')]);artifacts=self.package()
        with self.assertRaises(v.VerificationError):self.verify(artifacts)
        self.setUp();self.rejected(lambda:self.receipt['image']['platforms'].pop())
        self.setUp();self.rejected(lambda:self.receipt['addon'].update(version='0.2.0'))
    def test_refuses_duplicate_json_keys_and_damaged_oci_blob(self):
        artifacts=self.package()
        with self.assertRaises(v.VerificationError):self.verify(artifacts,b'{"schema_version":1,"schema_version":1}')
        self.setUp();blob=next(name for name in self.files if name.startswith('oci/blobs/'));self.files[blob]+=b'drift';artifacts=self.package()
        with self.assertRaises(v.VerificationError):self.verify(artifacts)


class ExtraBoundaryTests(unittest.TestCase):
    setUp=CandidateTests.setUp
    package=CandidateTests.package
    verify=CandidateTests.verify
    rejected=CandidateTests.rejected
    def test_refuses_independently_wrong_artifact_name(self):
        self.rejected(lambda:self.authority.artifact.update(name='receipt-selected-arbitrary-artifact'))
    def test_refuses_actual_zip_symlink(self):
        entry=zipfile.ZipInfo('link');entry.create_system=3;entry.external_attr=(stat.S_IFLNK|0o777)<<16
        artifacts=self.package([(entry,b'/etc/passwd')])
        with self.assertRaises(v.VerificationError):self.verify(artifacts)
    def test_refuses_dynamic_dependencies_and_unsupported_extra_host_entries(self):
        header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF'+bytes([2,1,1])+bytes(9),2,62,1,0,64,0,0,64,56,2,0,0,0)
        load=struct.pack('<IIQQQQQQ',1,5,176,0,0,32,32,4096)
        dynamic=struct.pack('<IIQQQQQQ',2,4,176,0,0,32,32,8)
        data=header+load+dynamic+struct.pack('<QQQQ',1,0,0,0)
        key='wolf-manager-host-v0.1.0-x86_64-unknown-linux-musl.tar.gz';self.files[key]=archive([('bin/wolf-manager-host',data,'file')]);artifacts=self.package()
        with self.assertRaises(v.VerificationError):self.verify(artifacts)
        self.setUp();self.files[key]=archive([('bin/wolf-manager-host',elf(62),'file'),('unexpected.sh',b'bad','file')]);artifacts=self.package()
        with self.assertRaises(v.VerificationError):self.verify(artifacts)
    def test_malformed_oci_shape_is_a_controlled_refusal(self):
        self.files['oci/index.json']=encoded({'schemaVersion':2,'manifests':[None]});artifacts=self.package()
        with self.assertRaises(v.VerificationError):self.verify(artifacts)

class RemainingBoundaryTests(unittest.TestCase):
    setUp=CandidateTests.setUp
    package=CandidateTests.package
    verify=CandidateTests.verify
    rejected=CandidateTests.rejected
    def test_refuses_interpreter_and_non_executable_host_modes(self):
        key='wolf-manager-host-v0.1.0-x86_64-unknown-linux-musl.tar.gz'
        header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF'+bytes([2,1,1])+bytes(9),2,62,1,0,64,0,0,64,56,2,0,0,0)
        load=struct.pack('<IIQQQQQQ',1,5,176,0,0,16,16,4096)
        interpreter=struct.pack('<IIQQQQQQ',3,4,176,0,0,16,16,1)
        self.files[key]=archive([('bin/wolf-manager-host',header+load+interpreter+b'/lib/ld.so\0'+bytes(5),'file')]);artifacts=self.package()
        with self.assertRaisesRegex(v.VerificationError,'dynamic_or_malformed_elf'):self.verify(artifacts)
        self.setUp();out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w:gz') as tar:
            data=elf(62);entry=tarfile.TarInfo('bin/wolf-manager-host');entry.size=len(data);entry.mode=0o644;tar.addfile(entry,io.BytesIO(data))
        self.files[key]=out.getvalue();artifacts=self.package()
        with self.assertRaisesRegex(v.VerificationError,'target_executable'):self.verify(artifacts)
    def test_refuses_missing_check_evidence_in_bound_bundle(self):
        del self.files['evidence/sonar.json'];artifacts=self.package()
        with self.assertRaisesRegex(v.VerificationError,'missing_check_evidence'):self.verify(artifacts)
    def test_refuses_api_redirect_before_authorization_can_leave_origin(self):
        import urllib.request
        request=urllib.request.Request('https://api.github.com/repos/'+REPO+'/actions/runs/99',headers={'Authorization':'Bearer fixture-only'})
        with self.assertRaisesRegex(v.VerificationError,'api_redirect_refused'):
            v._NoRedirect().redirect_request(request,None,302,'Found',{},'https://attacker.invalid')
    def test_refuses_archive_control_characters(self):
        artifacts=self.package([('evil\nfile',b'bad')])
        with self.assertRaisesRegex(v.VerificationError,'archive_path'):self.verify(artifacts)

if __name__ == '__main__':
    unittest.main()
