"""Recoverable, revision-bound file activation. No glob-selected backups."""
import ast
import fcntl
import hashlib
import json
import os
import stat
import uuid
from contextlib import contextmanager


def sha(data):
    return hashlib.sha256(data).hexdigest()


@contextmanager
def locked_target(path):
    path = os.path.abspath(path)
    parts = path.split(os.sep)
    parent = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    lock = None
    try:
        for part in parts[1:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent);parent=fd
        name=parts[-1]
        lock=os.open('.'+name+'.evolution.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=parent)
        if not stat.S_ISREG(os.fstat(lock).st_mode):raise ValueError('INVALID_LOCK_FILE')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield parent,name
    finally:
        if lock is not None:
            os.close(lock)
        os.close(parent)


def read_at(parent,name):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size>1048576:
            raise ValueError('INVALID_TARGET_FILE')
        return stream.read(1048577),stat.S_IMODE(info.st_mode)


def replace_at(parent,name,data,mode):
    temporary='.'+name+'.tmp.'+uuid.uuid4().hex
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fchmod(stream.fileno(),mode);os.fsync(stream.fileno())
        os.replace(temporary,name,src_dir_fd=parent,dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:os.unlink(temporary,dir_fd=parent)
        except FileNotFoundError:pass


def _init(store):
    with store.events._get_connection() as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS ciph_file_activations (grant_id TEXT PRIMARY KEY, target TEXT, candidate_hash TEXT, base_hash TEXT, base_bytes BLOB, mode INTEGER, state TEXT, evidence_hash TEXT)')


def activate(artifact,grant,store):
    _init(store)
    target=os.path.abspath(artifact['target_file'])
    if target != os.path.abspath(grant.target_file_path):raise ValueError('TARGET_PATH_MISMATCH')
    # Read exactly the approved bytes; no header stripping or newline rewriting.
    with locked_target(artifact['staged_file']) as (p,n):candidate,_=read_at(p,n)
    if sha(candidate)!=grant.candidate_hash:raise ValueError('CANDIDATE_HASH_MISMATCH')
    ast.parse(candidate.decode('utf-8'))
    with locked_target(target) as (parent,name):
        baseline,mode=read_at(parent,name)
        if sha(baseline)!=grant.base_file_hash:raise ValueError('CONCURRENT_MODIFICATION_DETECTED')
        prepared=store.record('ACTIVATION_PREPARED',{'grant_hash':sha(grant.compute_canonical_payload()),
            'target':target,'base_hash':grant.base_file_hash,'candidate_hash':grant.candidate_hash,'mode':mode})
        with store.events._get_connection() as conn:
            conn.execute('INSERT INTO ciph_file_activations VALUES (?,?,?,?,?,?,?,?)',
                (grant.grant_id,target,grant.candidate_hash,grant.base_file_hash,baseline,mode,'PREPARED',prepared))
        try:
            if not grant.verify_signature(store.trust)[0]:raise ValueError('GRANT_EXPIRED_OR_REVOKED')
            if read_at(parent,name)[0]!=baseline:raise ValueError('CONCURRENT_MODIFICATION_DETECTED')
            replace_at(parent,name,candidate,mode)
            evidence=store.record('ACTIVATED',{'grant_id':grant.grant_id,'candidate_hash':grant.candidate_hash,'target':target})
            with store.events._get_connection() as conn:
                conn.execute("UPDATE ciph_file_activations SET state='ACTIVE' WHERE grant_id=?",(grant.grant_id,))
            return True,'Successfully applied approved revision; evidence '+evidence
        except Exception as exc:
            # Never blindly copy a backup after an ambiguous replace/fsync failure.
            with store.events._get_connection() as conn:
                conn.execute("UPDATE ciph_file_activations SET state='RECONCILIATION_REQUIRED' WHERE grant_id=?",(grant.grant_id,))
            return False,'RECONCILIATION_REQUIRED: '+str(exc)


def restore(grant,store):
    _init(store)
    with store.events._get_connection() as conn:
        row=conn.execute('SELECT * FROM ciph_file_activations WHERE grant_id=?',(grant.grant_id,)).fetchone()
    if not row:raise ValueError('NO_BOUND_ROLLBACK_CHECKPOINT')
    evidence=store.verify(row['evidence_hash'],'ACTIVATION_PREPARED')
    target=os.path.abspath(grant.target_file_path)
    if (evidence['grant_hash']!=sha(grant.compute_canonical_payload()) or evidence['target']!=target
            or evidence.get('mode')!=row['mode'] or row['target']!=target or sha(row['base_bytes'])!=grant.base_file_hash
            or row['base_hash']!=grant.base_file_hash or row['candidate_hash']!=grant.candidate_hash):
        raise ValueError('ROLLBACK_CHECKPOINT_TAMPERED')
    with locked_target(target) as (parent,name):
        current,_=read_at(parent,name)
        if sha(current)==grant.base_file_hash:
            outcome='ALREADY_RESTORED'
        elif sha(current)==grant.candidate_hash:
            replace_at(parent,name,row['base_bytes'],row['mode']);outcome='RESTORED'
        else:raise ValueError('ACTIVE_REVISION_MISMATCH: does not match candidate; newer deployment preserved')
        store.record('ROLLED_BACK',{'grant_id':grant.grant_id,'candidate_hash':grant.candidate_hash,'target':target,'outcome':outcome})
        with store.events._get_connection() as conn:
            conn.execute("UPDATE ciph_file_activations SET state='ROLLED_BACK' WHERE grant_id=?",(grant.grant_id,))
        return True,outcome
