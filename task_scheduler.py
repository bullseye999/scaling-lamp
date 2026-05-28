#!/usr/bin/env python3
# task_scheduler.py - Automated background tasks

import threading
import time
import schedule
from datetime import datetime, timedelta
from typing import Dict, Any, Callable

class TaskScheduler:
    """
    Automated task scheduling - runs jobs in background
    """
    
    def __init__(self, vault, module_manager):
        self.vault = vault
        self.module_manager = module_manager
        self.scheduled_tasks = {}
        self.is_running = False
        self.scheduler_thread = None
        
        # Default schedule
        self.default_schedule = {
            'osint_scan': {'interval_hours': 6, 'enabled': True},
            'memory_cleanup': {'interval_days': 1, 'enabled': True},
            'backup_vault': {'interval_hours': 12, 'enabled': True}
        }
        
        # Load saved schedule
        self._load_schedule()
    
    def _load_schedule(self):
        """Load schedule from vault"""
        schedule_data = self.vault.get_config("task_schedule")
        if schedule_data:
            try:
                import json
                self.default_schedule = json.loads(schedule_data)
            except Exception:
                pass
    
    def _save_schedule(self):
        """Save schedule to vault"""
        import json
        self.vault.set_config("task_schedule", json.dumps(self.default_schedule))
    
    def start_scheduler(self):
        """Start the background scheduler"""
        if self.is_running:
            return "‖ Scheduler already running ‖"
        
        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        # Schedule default tasks
        self._schedule_default_tasks()
        
        return "‖ Task scheduler started ‖"
    
    def stop_scheduler(self):
        """Stop the background scheduler"""
        self.is_running = False
        schedule.clear()
        return "‖ Task scheduler stopped ‖"
    
    def _run_scheduler(self):
        """Main scheduler loop (runs in background thread)"""
        while self.is_running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    def _schedule_default_tasks(self):
        """Schedule the default tasks"""
        # OSINT scan every 6 hours
        if self.default_schedule['osint_scan']['enabled']:
            schedule.every(self.default_schedule['osint_scan']['interval_hours']).hours.do(
                self._run_osint_scan
            )
        
        # Memory cleanup daily
        if self.default_schedule['memory_cleanup']['enabled']:
            schedule.every(self.default_schedule['memory_cleanup']['interval_days']).days.do(
                self._run_memory_cleanup
            )

        # Autonomous OSINT cycle every 4 hours
        schedule.every(4).hours.do(self._run_autonomous_osint)
        
        # Backup vault every 12 hours
        if self.default_schedule['backup_vault']['enabled']:
            schedule.every(self.default_schedule['backup_vault']['interval_hours']).hours.do(
                self._run_backup
            )
    
    def _run_osint_scan(self):
        """Automated OSINT scan"""
        try:
            osint_module = self.module_manager.get_module('osint')
            if osint_module:
                results = osint_module.monitor_all_feeds()
                alert_count = len(results.get('alerts', []))
                # Store scan result
                self.vault.store_conversation(
                    "🕵️ AUTO-OSINT SCAN",
                    f"Time: {datetime.now()}\nItems: {sum(len(items) for items in results.get('results', {}).values())}\nAlerts: {alert_count}",
                    context_tag="auto_task"
                )
                print(f"‖ AUTO-OSINT: {alert_count} alerts found ‖")
        except Exception as e:
            print(f"‖ AUTO-OSINT Error: {e} ‖")
    
    def _run_memory_cleanup(self):
        """Automated memory cleanup"""
        try:
            # Simple cleanup: remove conversations older than 30 days
            conn = self.vault._get_connection()
            c = conn.cursor()
            thirty_days_ago = time.time() - (30 * 24 * 60 * 60)
            c.execute('DELETE FROM conversations WHERE timestamp < ?', (thirty_days_ago,))
            conn.commit()
            conn.close()
            
            self.vault.store_conversation(
                "🧹 AUTO-MEMORY CLEANUP",
                f"Time: {datetime.now()}\nRemoved conversations older than 30 days",
                context_tag="auto_task"
            )
            print("‖ AUTO-MEMORY: Cleanup completed ‖")
        except Exception as e:
            print(f"‖ AUTO-MEMORY Error: {e} ‖")
    
    def _run_backup(self):
        """Automated vault backup"""
        try:
            import shutil
            import os
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"system_backup_{timestamp}.db"
            shutil.copy2("secure_vault.db", backup_file)
            
            self.vault.store_conversation(
                "💾 AUTO-BACKUP",
                f"Time: {datetime.now()}\nBackup file: {backup_file}",
                context_tag="auto_task"
            )
            print(f"‖ AUTO-BACKUP: {backup_file} created ‖")
        except Exception as e:
            print(f"‖ AUTO-BACKUP Error: {e} ‖")
    
    def schedule_custom_task(self, task_func: Callable, interval_minutes: int, task_name: str):
        """Schedule a custom task"""
        schedule.every(interval_minutes).minutes.do(task_func)
        self.scheduled_tasks[task_name] = {
            'function': task_func,
            'interval': interval_minutes,
            'last_run': None
        }
        return f"‖ Custom task '{task_name}' scheduled every {interval_minutes} minutes ‖"
    
    def _run_autonomous_osint(self):
        """Scheduled task for autonomous OSINT"""
        try:
            osint_module = self.module_manager.get_module('osint')
            if osint_module:
                # Run full autonomous cycle
                result = osint_module.autonomous_osint_cycle()
            
                # Find money-making opportunities
                opportunities = osint_module.find_monetizable_threats()
            
                # Store summary
                self.vault.store_conversation(
                    "AUTO_OSINT_CYCLE",
                    f"Threats analyzed: {result.get('threats_analyzed', 0)}\n"
                    f"Critical alerts: {result.get('critical_alerts', 0)}\n"
                    f"Money ops found: {len(opportunities)}",
                    context_tag="auto_osint"
                )
            
                print(f"🤖 AUTO-OSINT: {result.get('threats_analyzed', 0)} threats, {len(opportunities)} money ops")
        except Exception as e:
            print(f"‖ AUTO-OSINT Error: {e} ‖")
    
    def get_scheduler_status(self) -> Dict[str, Any]:
        """Get scheduler status"""
        return {
            'running': self.is_running,
            'scheduled_jobs': len(schedule.jobs),
            'default_schedule': self.default_schedule,
            'custom_tasks': list(self.scheduled_tasks.keys())
        }
    
    def update_schedule(self, task_name: str, enabled: bool = None, interval: int = None):
        """Update task schedule"""
        if task_name in self.default_schedule:
            if enabled is not None:
                self.default_schedule[task_name]['enabled'] = enabled
            if interval is not None:
                self.default_schedule[task_name]['interval_hours'] = interval
            
            self._save_schedule()
            # Restart scheduler with new settings
            if self.is_running:
                schedule.clear()
                self._schedule_default_tasks()
            
            return f"‖ Schedule updated for {task_name} ‖"
        return f"‖ Unknown task: {task_name} ‖"


if __name__ == "__main__":
    from cipher_vault import CipherVault
    from module_manager import ModuleManager
    
    vault = CipherVault()
    manager = ModuleManager(vault)
    scheduler = TaskScheduler(vault, manager)
    
    print("🧪 Testing Task Scheduler:")
    print(scheduler.start_scheduler())
    print("Status:", scheduler.get_scheduler_status())
    time.sleep(2)
    print(scheduler.stop_scheduler())