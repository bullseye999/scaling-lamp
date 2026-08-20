#!/usr/bin/env python3
# job_queue.py - Background job queue and multi-threaded worker pool

import time
import uuid
import threading
import json
from typing import Dict, Any, Callable, Optional
from datetime import datetime
from queue import Queue

class JobQueue:
    """Asynchronous background job queue with thread workers to prevent blocking interactive chat."""

    def __init__(self):
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
        # Clear queue to unblock workers
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except:
                break

    def _worker_loop(self):
        """Worker thread: processes jobs from queue."""
        while self.running:
            try:
                job = self.queue.get(timeout=1)
                if job is None:
                    continue
                
                job_id = job['job_id']
                func = job['func']
                args = job.get('args', [])
                kwargs = job.get('kwargs', {})
                
                # Update job status
                self.jobs[job_id]['status'] = 'running'
                self.jobs[job_id]['started_at'] = time.time()
                
                try:
                    result = func(*args, **kwargs)
                    self.jobs[job_id]['status'] = 'completed'
                    self.jobs[job_id]['result'] = result
                    self.jobs[job_id]['completed_at'] = time.time()
                except Exception as e:
                    self.jobs[job_id]['status'] = 'failed'
                    self.jobs[job_id]['error'] = str(e)
                    self.jobs[job_id]['completed_at'] = time.time()
                
            except Exception:
                pass

    def submit(self, func: Callable, *args, **kwargs) -> str:
        """Submit a job to be executed in background. Returns job_id."""
        job_id = str(uuid.uuid4())[:8]
        self.jobs[job_id] = {
            'job_id': job_id,
            'status': 'queued',
            'created_at': time.time(),
            'func_name': func.__name__,
            'args': str(args)[:100],
        }
        self.queue.put({
            'job_id': job_id,
            'func': func,
            'args': args,
            'kwargs': kwargs
        })
        return job_id

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

    def update_progress(self, job_id: str, progress: int, message: str = ""):
        """Update progress on a running job"""
        if job_id in self.jobs:
            self.jobs[job_id]['progress'] = progress
            self.jobs[job_id]['progress_message'] = message

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