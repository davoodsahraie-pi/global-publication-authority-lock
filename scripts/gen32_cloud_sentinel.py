#!/usr/bin/env python3
"""SYNTHETIC ONLY. Does not authorize or execute GLOBAL PUBLICATION.

Proves local SQLite process-race invariants on one filesystem. Does NOT prove
cross-run GitHub durability or real Assembler/PPGES/Word qualification.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

SCHEMA = "GEN32_CLOUD_SENTINEL_LOCAL_PROOF/1.0.0"
SQL = """
PRAGMA foreign_keys = ON;
CREATE TABLE redemptions (
    attempt_key TEXT PRIMARY KEY NOT NULL,
    dispatch_ref TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL UNIQUE,
    executor_id TEXT NOT NULL,
    package_sha TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status = 'CONSUMED')
);
CREATE TABLE closures (
    attempt_key TEXT PRIMARY KEY NOT NULL REFERENCES redemptions(attempt_key),
    closure_run TEXT NOT NULL UNIQUE,
    outcome TEXT NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILED', 'UNKNOWN')),
    artifact_sha TEXT
);
CREATE TRIGGER redemptions_no_update BEFORE UPDATE ON redemptions BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_REDEMPTION'); END;
CREATE TRIGGER redemptions_no_delete BEFORE DELETE ON redemptions BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_REDEMPTION'); END;
CREATE TRIGGER closures_no_update BEFORE UPDATE ON closures BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_CLOSURE'); END;
CREATE TRIGGER closures_no_delete BEFORE DELETE ON closures BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_CLOSURE'); END;
"""

# IMPORTANT: this demonstrator has no GitHub-committed grant check, protected
# one-time cross-run store, or actual dispatch privileges. It is not a broker.
# Fixed synthetic IDs, intentionally unrelated to any real owner authorization.
PACKAGE_SHA = hashlib.sha256(b'synthetic-not-a-real-package').hexdigest()

def init_ephemeral(db: Path):
    if db.exists():
        raise ValueError('EPHEMERAL_DB_ALREADY_EXISTS')
    db.parent.mkdir(parents=True, exist_ok=True)
    cx = sqlite3.connect(db, timeout=20.0)
    try:
        cx.execute('PRAGMA journal_mode=DELETE')
        cx.execute('PRAGMA synchronous=EXTRA')
        cx.executescript(SQL)
        cx.commit()
    finally:
        cx.close()


def existing_db(db: Path):
    if not db.is_file():
        raise ValueError('NO_EXISTING_STORE_FAIL_CLOSED')
    cx = sqlite3.connect(f'file:{db.as_posix()}?mode=rw', uri=True, timeout=20.0)
    cx.execute('PRAGMA busy_timeout=20000')
    cx.execute('PRAGMA foreign_keys=ON')
    cx.execute('PRAGMA synchronous=EXTRA')
    if cx.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
        cx.close()
        raise ValueError('STORE_INTEGRITY_FAIL_CLOSED')
    return cx


def consume(db: Path, attempt: str, dispatch: str, run: str, executor: str):
    cx=existing_db(db)
    try:
        cx.execute('BEGIN IMMEDIATE')
        cx.execute('INSERT INTO redemptions VALUES (?,?,?,?,?,?)',
                   (attempt, dispatch, run, executor, PACKAGE_SHA, 'CONSUMED'))
        cx.commit()
        return True
    except sqlite3.IntegrityError:
        cx.rollback()
        return False
    finally:
        cx.close()


def close_once(db: Path, attempt: str, closure_run: str, outcome: str):
    cx=existing_db(db)
    try:
        cx.execute('BEGIN IMMEDIATE')
        cx.execute('INSERT INTO closures VALUES (?,?,?,?)',
                   (attempt, closure_run, outcome, None))
        cx.commit()
        return True
    except sqlite3.IntegrityError:
        cx.rollback()
        return False
    finally:
        cx.close()


def child(args):
    try:
        ok=consume(Path(args.db),args.attempt,args.dispatch,args.run,args.executor)
    except (OSError,ValueError,sqlite3.DatabaseError) as e:
        print(json.dumps({'status':'DENY','reason':type(e).__name__}))
        return 5
    if not ok:
        print(json.dumps({'status':'DENY','reason':'ALREADY_CONSUMED'}))
        return 3
    if args.crash_after_commit:
        # Synthetic crash: consumed ticket must never be automatically recovered.
        os._exit(77)
    # This is a dummy marker, never a real producer, import, PDF or DOCX.
    Path(args.marker).open('x', encoding='utf-8').write('SYNTHETIC_SENTINEL_ONLY\n')
    print(json.dumps({'status':'SYNTHETIC_ADMITTED'}))
    return 0


def call_child(db, marker, attempt='SYNTHETIC-A01', dispatch='SYNTHETIC-D01',
               run='SYNTHETIC-R01', executor='SYNTHETIC-E01', crash=False):
    argv=[sys.executable,'-I','-B',str(Path(__file__).resolve()),'claim',
          '--db',str(db),'--marker',str(marker),'--attempt',attempt,
          '--dispatch',dispatch,'--run',run,'--executor',executor]
    if crash: argv.append('--crash-after-commit')
    return subprocess.run(argv, capture_output=True, text=True, timeout=40)


def test_all():
    cases=[]
    def check(name,cond):
        cases.append({'case':name,'pass':bool(cond)})
    with tempfile.TemporaryDirectory(prefix='GEN32_SENTINEL_NO_REAL_DATA_') as td:
        root=Path(td)
        db=root/'receipts.sqlite3'; marker=root/'one_synthetic_side_effect.txt'
        init_ephemeral(db)
        cx=existing_db(db)
        check('SQLITE_SCHEMA_EXISTS', bool(cx.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='redemptions'").fetchone()))
        cx.close()
        # 20 distinct processes starting together, against the same attempt.
        with ThreadPoolExecutor(max_workers=20) as executor:
            race=list(executor.map(lambda i: call_child(db,marker,run=f'SYNTHETIC-R{i:02d}',dispatch=f'SYNTHETIC-D{i:02d}'),range(20)))
        check('TWENTY_PROCESSES_ONE_ADMISSION', sum(p.returncode==0 for p in race)==1)
        check('TWENTY_PROCESSES_NINETEEN_DENIED',sum(p.returncode==3 for p in race)==19)
        check('SENTINEL_SIDE_EFFECT_ONCE', marker.exists() and marker.read_text()=='SYNTHETIC_SENTINEL_ONLY\n')
        cx=existing_db(db)
        check('DURABLE_ONE_REDEMPTION',cx.execute('SELECT count(*) FROM redemptions').fetchone()[0]==1)
        winning_run=cx.execute('SELECT run_id FROM redemptions').fetchone()[0]
        cx.close()
        check('SAME_ATTEMPT_REPLAY_REJECTED',call_child(db,marker).returncode==3)
        check('RUN_REUSE_FOR_ANOTHER_ATTEMPT_REJECTED',not consume(db,'SYNTHETIC-A02','SYNTHETIC-D21',winning_run,'SYNTHETIC-E01'))
        check('DISPATCH_REUSE_FOR_ANOTHER_ATTEMPT_REJECTED',not consume(db,'SYNTHETIC-A02',f'SYNTHETIC-D{winning_run.removeprefix("SYNTHETIC-R")}', 'SYNTHETIC-R22','SYNTHETIC-E01'))
        check('NEW_ATTEMPT_DIFFERENT_RUN_ALLOWED_SYNTHETIC',consume(db,'SYNTHETIC-A02','SYNTHETIC-D23','SYNTHETIC-R23','SYNTHETIC-E01'))
        check('CLOSE_ONCE',close_once(db,'SYNTHETIC-A01','SYNTHETIC-C01','SUCCESS'))
        check('CLOSE_REPLAY_DENIED',not close_once(db,'SYNTHETIC-A01','SYNTHETIC-C02','FAILED'))
        cx=existing_db(db)
        try:
            cx.execute("DELETE FROM redemptions WHERE attempt_key='SYNTHETIC-A01'")
            deletion_forbidden=False
        except sqlite3.DatabaseError:
            deletion_forbidden=True
        cx.rollback()
        check('REDEMPTION_IMMUTABLE',deletion_forbidden)
        try:
            cx.execute("UPDATE closures SET outcome='FAILED' WHERE attempt_key='SYNTHETIC-A01'")
            mutation_forbidden=False
        except sqlite3.DatabaseError:
            mutation_forbidden=True
        cx.rollback();cx.close()
        check('CLOSE_IMMUTABLE',mutation_forbidden)
        missing=root/'unprovisioned.sqlite3'
        try:
            consume(missing,'SYNTHETIC-A03','SYNTHETIC-D03','SYNTHETIC-R03','SYNTHETIC-E01')
            missing_denied=False
        except (ValueError,sqlite3.DatabaseError):
            missing_denied=True
        check('MISSING_STORE_FAIL_CLOSED',missing_denied and not missing.exists())
        crash_marker=root/'crash_marker.txt'
        crash=call_child(db,crash_marker,attempt='SYNTHETIC-A04',dispatch='SYNTHETIC-D04',run='SYNTHETIC-R04',crash=True)
        check('CRASH_AFTER_COMMIT_NO_OUTPUT',crash.returncode==77 and not crash_marker.exists())
        check('CRASH_REPLAY_STAYS_CONSUMED',call_child(db,crash_marker,attempt='SYNTHETIC-A04',dispatch='SYNTHETIC-D04',run='SYNTHETIC-R04').returncode==3)
        check('NO_CRASH_RETRY_OUTPUT',not crash_marker.exists())
        lastcx=existing_db(db)
        check('STORE_INTEGRITY_SURVIVES_CRASH',lastcx.execute('PRAGMA integrity_check').fetchone()[0]=='ok')
        lastcx.close()
        check('NO_REAL_GENERATOR_IMPORTED',not any(x.startswith('global_publication') for x in sys.modules))
    passed=sum(c['pass'] for c in cases)
    report={'schema':SCHEMA,'test_mode':'LOCAL_EPHEMERAL_SQLITE_SIMULATION',
           'python_version':sys.version.split()[0],'total':len(cases),'passed':passed,
           'result':'PASS' if passed==len(cases) else 'FAIL',
           'cases':cases,
           'limitations':['NO_ACTUAL_GITHUB_CAS_PROOF','NO_CROSS_RUN_PERSISTENCE',
                          'NO_DEPLOYED_RUNNER_TEST','NO_ASSEMBLER_EXECUTION',
                          'NO_AUTHORITY_CHANGE','NO_OFFICIAL_DISPATCH_GRANT',
                          'NO_PRIVATE_C1_PPGES_OR_PDF']}
    print(json.dumps(report,indent=2,ensure_ascii=False))
    return 0 if passed==len(cases) else 1


def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='cmd',required=True)
    sub.add_parser('selftest')
    c=sub.add_parser('claim')
    for s in ('db','marker','attempt','dispatch','run','executor'):
        c.add_argument('--'+s,required=True)
    c.add_argument('--crash-after-commit',action='store_true')
    args=p.parse_args()
    return test_all() if args.cmd=='selftest' else child(args)
if __name__=='__main__':raise SystemExit(main())
