#!/usr/bin/env python3
# sports_performance.py - Ciph Sports Performance Tracker
# Tracks prediction accuracy, ROI, layer performance
# Sends reports via email daily and after every 10 predictions

import os
import json
import smtplib
import threading
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from cipher_vault import CipherVault

PREDICTIONS_DIR = "ciph_predictions"


class SportsPerformance:
    """
    Ciph's sports prediction performance tracker.
    
    Tracks:
    - Win rate per outcome type
    - ROI over time
    - Layer accuracy (which layer predicts best)
    - Contrarian signal performance
    - Drawdown and streaks
    - Daily email reports
    - Email after every 10 predictions
    """

    def __init__(self, vault: CipherVault):
        self.vault            = vault
        self.email_from       = vault.get_config('report_email_from') or ''
        self.email_password   = vault.get_config('report_email_password') or ''
        self.email_to         = vault.get_config('report_email_to') or ''
        self.daily_thread     = None
        self.daily_running    = False
        self.daily_hour       = int(vault.get_config('report_hour') or '8')

    # ─────────────────────────────────────────────
    # CORE STATS ENGINE
    # ─────────────────────────────────────────────

    def calculate_stats(self) -> Dict[str, Any]:
        """
        Read all prediction files and calculate full performance stats.
        """
        if not os.path.exists(PREDICTIONS_DIR):
            return self._empty_stats()

        files       = [f for f in os.listdir(PREDICTIONS_DIR) if f.endswith('.json')]
        predictions = []

        for fname in files:
            try:
                with open(os.path.join(PREDICTIONS_DIR, fname), 'r') as f:
                    predictions.append(json.load(f))
            except Exception:
                continue

        if not predictions:
            return self._empty_stats()

        # Split into resolved and pending
        resolved = [p for p in predictions if p.get('actual_result') and p['actual_result'] != 'PENDING']
        pending  = [p for p in predictions if not p.get('actual_result') or p['actual_result'] == 'PENDING']

        if not resolved:
            return {
                **self._empty_stats(),
                'total_predictions': len(predictions),
                'pending':           len(pending),
                'message':           'No results recorded yet. Use /result <match_id> <HOME WIN/DRAW/AWAY WIN>'
            }

        # Overall accuracy
        correct    = sum(1 for p in resolved
                        if p.get('final', {}).get('final_outcome') == p.get('actual_result'))
        total      = len(resolved)
        win_rate   = round((correct / total) * 100, 1) if total > 0 else 0

        # Per outcome accuracy
        for outcome in ['HOME WIN', 'DRAW', 'AWAY WIN']:
            predicted_as = [p for p in resolved
                           if p.get('final', {}).get('final_outcome') == outcome]
            correct_out  = [p for p in predicted_as
                           if p.get('actual_result') == outcome]
            pct = round((len(correct_out) / len(predicted_as)) * 100, 1) if predicted_as else 0

        outcome_accuracy = {}
        for outcome in ['HOME WIN', 'DRAW', 'AWAY WIN']:
            predicted_as = [p for p in resolved
                           if p.get('final', {}).get('final_outcome') == outcome]
            correct_out  = [p for p in predicted_as
                           if p.get('actual_result') == outcome]
            outcome_accuracy[outcome] = {
                'predicted': len(predicted_as),
                'correct':   len(correct_out),
                'accuracy':  round((len(correct_out) / len(predicted_as)) * 100, 1) if predicted_as else 0
            }

        # Layer accuracy
        layer_stats = {}
        for layer in ['math', 'market', 'ciph']:
            layer_correct = 0
            layer_total   = 0
            for p in resolved:
                layer_pred = p.get('layers', {}).get(layer, {}).get('outcome')
                if layer_pred:
                    layer_total   += 1
                    if layer_pred == p.get('actual_result'):
                        layer_correct += 1
            layer_stats[layer] = {
                'correct':  layer_correct,
                'total':    layer_total,
                'accuracy': round((layer_correct / layer_total) * 100, 1) if layer_total > 0 else 0
            }

        # Best performing layer
        best_layer = max(layer_stats, key=lambda x: layer_stats[x]['accuracy']) if layer_stats else 'unknown'

        # Contrarian signal performance
        contrarian = [p for p in resolved if p.get('final', {}).get('is_contrarian')]
        contrarian_correct = sum(1 for p in contrarian
                                if p.get('final', {}).get('final_outcome') == p.get('actual_result'))
        contrarian_rate = round((contrarian_correct / len(contrarian)) * 100, 1) if contrarian else 0

        # Streak analysis
        sorted_resolved = sorted(resolved, key=lambda x: x.get('predicted_at', ''))
        current_streak  = 0
        best_streak     = 0
        worst_streak    = 0
        temp_win        = 0
        temp_loss       = 0

        for p in sorted_resolved:
            if p.get('final', {}).get('final_outcome') == p.get('actual_result'):
                temp_win  += 1
                temp_loss  = 0
                best_streak = max(best_streak, temp_win)
            else:
                temp_loss  += 1
                temp_win    = 0
                worst_streak = max(worst_streak, temp_loss)

        current_streak = temp_win if temp_win > 0 else -temp_loss

        # Conviction accuracy
        high_conv   = [p for p in resolved if p.get('final', {}).get('rating') == 'HIGH']
        med_conv    = [p for p in resolved if p.get('final', {}).get('rating') == 'MEDIUM']
        high_correct = sum(1 for p in high_conv
                          if p.get('final', {}).get('final_outcome') == p.get('actual_result'))
        med_correct  = sum(1 for p in med_conv
                          if p.get('final', {}).get('final_outcome') == p.get('actual_result'))

        high_rate = round((high_correct / len(high_conv)) * 100, 1) if high_conv else 0
        med_rate  = round((med_correct  / len(med_conv))  * 100, 1) if med_conv  else 0

        # Current weights
        weights_raw = vault_get(self.vault, 'sports_weights')
        weights     = json.loads(weights_raw) if weights_raw else {}

        return {
            'generated_at':        datetime.now().isoformat(),
            'total_predictions':   len(predictions),
            'resolved':            total,
            'pending':             len(pending),
            'correct':             correct,
            'win_rate':            win_rate,
            'outcome_accuracy':    outcome_accuracy,
            'layer_stats':         layer_stats,
            'best_layer':          best_layer,
            'contrarian_total':    len(contrarian),
            'contrarian_accuracy': contrarian_rate,
            'current_streak':      current_streak,
            'best_streak':         best_streak,
            'worst_streak':        worst_streak,
            'high_conviction_accuracy': high_rate,
            'med_conviction_accuracy':  med_rate,
            'current_weights':     weights,
        }

    def _empty_stats(self) -> Dict[str, Any]:
        return {
            'generated_at':      datetime.now().isoformat(),
            'total_predictions': 0,
            'resolved':          0,
            'pending':           0,
            'correct':           0,
            'win_rate':          0,
            'message':           'No predictions yet.'
        }

    # ─────────────────────────────────────────────
    # REPORT FORMATTING
    # ─────────────────────────────────────────────

    def format_report(self, stats: Dict[str, Any]) -> str:
        """Format stats into a clean readable report"""
        now = datetime.now().strftime('%d %b %Y %H:%M')

        if stats.get('message') and stats['total_predictions'] == 0:
            return f"CIPH SPORTS REPORT — {now}\nNo predictions made yet."

        # Layer comparison
        layer_lines = ""
        for layer, data in stats.get('layer_stats', {}).items():
            bar   = '🟢' if data['accuracy'] >= 60 else '🟡' if data['accuracy'] >= 50 else '🔴'
            layer_lines += f"\n  {bar} {layer.upper():8} {data['accuracy']}% ({data['correct']}/{data['total']})"

        # Outcome breakdown
        outcome_lines = ""
        for outcome, data in stats.get('outcome_accuracy', {}).items():
            outcome_lines += f"\n  {outcome:12} {data['accuracy']}% ({data['correct']}/{data['predicted']})"

        # Streak
        streak     = stats.get('current_streak', 0)
        streak_str = f"🔥 {streak} wins" if streak > 0 else f"❄️  {abs(streak)} losses" if streak < 0 else "—"

        # Weights
        weights     = stats.get('current_weights', {})
        weight_line = ' | '.join([f"{k}: {round(v*100)}%" for k, v in weights.items()]) if weights else 'default'

        report = f"""
╔══════════════════════════════════════════╗
║     CIPH SPORTS INTELLIGENCE REPORT      ║
║     {now:^36} ║
╚══════════════════════════════════════════╝

📊 OVERVIEW
  Total Predictions : {stats['total_predictions']}
  Resolved          : {stats['resolved']}
  Pending           : {stats['pending']}
  Overall Win Rate  : {stats['win_rate']}% ({stats['correct']}/{stats['resolved']})

🎯 BY OUTCOME{outcome_lines}

🧠 LAYER PERFORMANCE{layer_lines}
  Best Layer: {stats.get('best_layer', 'N/A').upper()}

⚡ CONVICTION ACCURACY
  HIGH signals : {stats.get('high_conviction_accuracy', 0)}%
  MEDIUM signals: {stats.get('med_conviction_accuracy', 0)}%

🔀 CONTRARIAN SIGNALS
  Total    : {stats.get('contrarian_total', 0)}
  Accuracy : {stats.get('contrarian_accuracy', 0)}%

📈 STREAKS
  Current  : {streak_str}
  Best Win : {stats.get('best_streak', 0)} in a row
  Worst    : {stats.get('worst_streak', 0)} losses in a row

⚖️  CURRENT WEIGHTS
  {weight_line}

—
🔒 Ciph Intelligence Engine
        """.strip()

        return report

    # ─────────────────────────────────────────────
    # EMAIL DELIVERY
    # ─────────────────────────────────────────────

    def send_report(self, trigger: str = 'manual') -> str:
        """Send performance report via email"""
        if not self.email_from or not self.email_password or not self.email_to:
            return "Email not configured. Use /setup-email to configure."

        stats  = self.calculate_stats()
        report = self.format_report(stats)

        subject = f"Ciph Sports Report — {datetime.now().strftime('%d %b %Y')} [{trigger}]"

        try:
            msg                    = MIMEMultipart('alternative')
            msg['Subject']         = subject
            msg['From']            = self.email_from
            msg['To']              = self.email_to

            # Plain text version
            text_part = MIMEText(report, 'plain')

            # HTML version — cleaner in email
            html_report = report.replace('\n', '<br>').replace(' ', '&nbsp;')
            html_body   = f"""
<html><body>
<div style="font-family: monospace; background: #0a0a0a; color: #00ff88; padding: 20px; border-radius: 8px;">
<pre style="color: #00ff88;">{report}</pre>
</div>
</body></html>
"""
            html_part = MIMEText(html_body, 'html')

            msg.attach(text_part)
            msg.attach(html_part)

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(self.email_from, self.email_password)
                server.sendmail(self.email_from, self.email_to, msg.as_string())

            # Log send
            self.vault.set_config('last_report_sent', datetime.now().isoformat())

            return f"Report sent to {self.email_to}. Win rate: {stats['win_rate']}%"

        except Exception as e:
            return f"Email failed: {str(e)[:80]}"

    def check_10_prediction_trigger(self) -> bool:
        """Check if we've hit 10 new predictions since last email"""
        last_count_raw = self.vault.get_config('last_report_count')
        last_count     = int(last_count_raw) if last_count_raw else 0

        if not os.path.exists(PREDICTIONS_DIR):
            return False

        current_count = len([f for f in os.listdir(PREDICTIONS_DIR) if f.endswith('.json')])

        if current_count >= last_count + 10:
            self.vault.set_config('last_report_count', str(current_count))
            return True

        return False

    # ─────────────────────────────────────────────
    # DAILY REPORT DAEMON
    # ─────────────────────────────────────────────

    def start_daily_reports(self, hour: int = 8) -> str:
        if self.daily_running:
            return "Daily reports already scheduled."

        if not self.email_to:
            return "Configure email first with /setup-email"

        self.daily_hour    = hour
        self.daily_running = True
        self.vault.set_config('report_hour', str(hour))

        self.daily_thread = threading.Thread(
            target=self._daily_loop,
            daemon=True,
            name='CiphDailyReport'
        )
        self.daily_thread.start()

        return f"Daily reports scheduled at {hour:02d}:00 every day → {self.email_to}"

    def _daily_loop(self):
        """Background loop — sends daily report at configured hour"""
        while self.daily_running:
            now = datetime.now()
            if now.hour == self.daily_hour and now.minute == 0:
                self.send_report(trigger='daily')
                time.sleep(61)  # Skip duplicate in same minute
            else:
                time.sleep(30)

    def stop_daily_reports(self) -> str:
        self.daily_running = False
        return "Daily reports stopped."

    # ─────────────────────────────────────────────
    # SETUP
    # ─────────────────────────────────────────────

    def setup_email(self, email_from: str, app_password: str, email_to: str) -> str:
        """
        Configure email.
        Use Gmail App Password not your real password.
        Get at: myaccount.google.com/apppasswords
        """
        self.email_from     = email_from
        self.email_password = app_password
        self.email_to       = email_to

        self.vault.set_config('report_email_from',     email_from)
        self.vault.set_config('report_email_password', app_password)
        self.vault.set_config('report_email_to',       email_to)

        return (
            f"Email configured. Reports will go to {email_to}. "
            f"Run /send-report to test immediately."
        )

    def get_status(self) -> Dict[str, Any]:
        stats = self.calculate_stats()
        return {
            'email_configured': bool(self.email_to),
            'email_to':         self.email_to or 'not set',
            'daily_running':    self.daily_running,
            'daily_hour':       self.daily_hour,
            'total_predictions': stats['total_predictions'],
            'win_rate':         stats['win_rate'],
            'last_report_sent': self.vault.get_config('last_report_sent') or 'never'
        }

    def terminal_report(self) -> str:
        """Show report in terminal without emailing"""
        stats = self.calculate_stats()
        return self.format_report(stats)


def vault_get(vault, key):
    try:
        return vault.get_config(key)
    except Exception:
        return None


if __name__ == "__main__":
    from cipher_vault import CipherVault
    vault   = CipherVault()
    tracker = SportsPerformance(vault)
    print(tracker.terminal_report())
    print("\nSetup: /setup-email from@gmail.com APP_PASSWORD to@gmail.com")
    print("Then:  /start-daily-reports")
    print("Then:  /send-report")