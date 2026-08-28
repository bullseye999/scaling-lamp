#!/usr/bin/env python3
# job_queue.py - Background job queue for long-running tasks

import time
import uuid
import threading
import json
from typing import Dict, Any, Callable, Optional
from datetime import datetime
from queue import Queue

class JobQueue:
    """Background job queue. Long tasks don't block chat and produce verifiable receipts."""

    def __init__(self, vault=None):
        self.vault = vault
        self.jobs: Dict[str, Dict] = {}
        self.queue = Queue()
        self.worker_thread = None
        self.running = False
        self.workers = []

    def start(self, num_workers: int = 2):
        """Start background workers."""
        self.running = True
        self.workers = []
        for i in range(num_workers):
            worker = threading.Thread(target=self._worker_loop, name=f"JobWorker-{i}", daemon=True)
            worker.start()
            self.workers.append(worker)

    def stop(self):
        """Stop all workers."""
        self.running = False
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except:
                break

    def _worker_loop(self):
        """Worker thread: processes jobs from queue and records progress/completion receipts."""
        while self.running:
            try:
                job = self.queue.get(timeout=1)
                if job is None:
                    continue
                
                job_id = job['job_id']
                func = job['func']
                args = job.get('args', [])
                kwargs = job.get('kwargs', {})
                tool_name = job.get('tool_name', 'tool')
                target = job.get('target', 'general')
                
                # Update job status & record progress
                self.jobs[job_id]['status'] = 'running'
                self.jobs[job_id]['started_at'] = time.time()
                
                if self.vault and hasattr(self.vault, 'store_progress_receipt'):
                    try:
                        self.vault.store_progress_receipt(
                            job_id=job_id,
                            tool_name=tool_name,
                            target=target,
                            phase='STARTED',
                            event='Execution worker started processing payload'
                        )
                    except Exception:
                        pass
                
                try:
                    result = func(*args, **kwargs)
                    self.jobs[job_id]['status'] = 'completed'
                    self.jobs[job_id]['result'] = result
                    self.jobs[job_id]['completed_at'] = time.time()
                    
                    if self.vault and hasattr(self.vault, 'store_completion_receipt'):
                        try:
                            res_dict = result if isinstance(result, dict) else {"output": str(result)}
                            self.vault.store_completion_receipt(
                                job_id=job_id,
                                tool_name=tool_name,
                                target=target,
                                results=res_dict,
                                exit_code=0
                            )
                        except Exception:
                            pass
                except Exception as e:
                    self.jobs[job_id]['status'] = 'failed'
                    self.jobs[job_id]['error'] = str(e)
                    self.jobs[job_id]['completed_at'] = time.time()
                    
                    if self.vault and hasattr(self.vault, 'store_completion_receipt'):
                        try:
                            self.vault.store_completion_receipt(
                                job_id=job_id,
                                tool_name=tool_name,
                                target=target,
                                results={"error": str(e)},
                                exit_code=1
                            )
                        except Exception:
                            pass
                
            except Exception:
                pass

    def submit(self, func: Callable, *args, tool_name: str = "", target: str = "", **kwargs) -> str:
        """Submit a job to be executed in background. Returns job_id and logs DISPATCH_RECEIPT."""
        prefix = tool_name[:3].upper() if tool_name else "JOB"
        job_id = f"{prefix}-{uuid.uuid4().hex[:6].upper()}"
        tool_name = tool_name or getattr(func, '__name__', 'task')
        target = target or (str(args[0]) if args else "general")
        
        self.jobs[job_id] = {
            'job_id': job_id,
            'status': 'queued',
            'created_at': time.time(),
            'tool_name': tool_name,
            'target': target,
            'func_name': getattr(func, '__name__', 'task'),
            'args': str(args)[:100],
        }
        
        # Log DISPATCH_RECEIPT
        if self.vault and hasattr(self.vault, 'store_dispatch_receipt'):
            try:
                self.vault.store_dispatch_receipt(
                    job_id=job_id,
                    tool_name=tool_name,
                    target=target,
                    initial_params={"args": str(args)[:100], "kwargs": str(kwargs)[:100]}
                )
            except Exception:
                pass

        self.queue.put({
            'job_id': job_id,
            'func': func,
            'args': args,
            'kwargs': kwargs,
            'tool_name': tool_name,
            'target': target
        })
        return job_id

    def update_progress(self, job_id: str, phase: str, message: str = "", metadata: Optional[Dict[str, Any]] = None):
        """Update progress on a running job and log PROGRESS_RECEIPT."""
        if job_id in self.jobs:
            self.jobs[job_id]['phase'] = phase
            self.jobs[job_id]['progress_message'] = message
            
            tool_name = self.jobs[job_id].get('tool_name', 'tool')
            target = self.jobs[job_id].get('target', 'general')
            
            if self.vault and hasattr(self.vault, 'store_progress_receipt'):
                try:
                    self.vault.store_progress_receipt(
                        job_id=job_id,
                        tool_name=tool_name,
                        target=target,
                        phase=phase,
                        event=message,
                        metadata=metadata
                    )
                except Exception:
                    pass

    def get_status(self, job_id: str) -> Optional[Dict]:
        """Get job status."""
        return self.jobs.get(job_id)

    def get_result(self, job_id: str) -> Optional[Any]:
        """Get job result if completed."""
        job = self.jobs.get(job_id)
        if job and job['status'] == 'completed':
            return job.get('result')
        return None

    def cancel_job(self, job_id: str) -> str:
        """Cancel a queued job"""
        job = self.jobs.get(job_id)
        if not job:
            return f"Job {job_id} not found"
        if job['status'] == 'queued':
            job['status'] = 'cancelled'
            return f"Job {job_id} cancelled"
        elif job['status'] == 'running':
            return f"Job {job_id} is currently running"
        return f"Job {job_id} already {job['status']}"

    def get_pending_count(self) -> int:
        """Get number of pending jobs."""
        return self.queue.qsize()

    def get_summary(self) -> str:
        """Get summary of all jobs."""
        if not self.jobs:
            return "No jobs in queue."
        
        queued = sum(1 for j in self.jobs.values() if j['status'] == 'queued')
        running = sum(1 for j in self.jobs.values() if j['status'] == 'running')
        completed = sum(1 for j in self.jobs.values() if j['status'] == 'completed')
        failed = sum(1 for j in self.jobs.values() if j['status'] == 'failed')
        
        return f"📋 Jobs: {queued} queued, {running} running, {completed} completed, {failed} failed"