#!/usr/bin/env python3
# sports_predictor.py - Ciph's demonic football prediction engine
# Multi-signal decision engine with feedback learning
# Architecture: Poisson + xG + Market Movement + News + Ciph Reasoning + Arbiter

import os
import json
import time
import hashlib
import threading
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from cipher_vault import CipherVault

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

FOOTBALL_API    = "https://api.football-data.org/v4"
PROXY_URL = "http://127.0.0.1:5001/v1/chat/completions"
OLLAMA_MODEL    = "llama3.1:8b"
LOGS_DIR        = "ciph_sports_logs"
PREDICTIONS_DIR = "ciph_predictions"

# Layer weights — auto-adjusted based on performance
DEFAULT_WEIGHTS = {
    'math':   0.40,
    'market': 0.30,
    'news':   0.10,
    'ciph':   0.20
}

# Leagues to monitor
LEAGUES = {
    'premier_league':    'PL',
    'champions_league':  'CL',
    'la_liga':           'PD',
    'serie_a':           'SA',
    'bundesliga':        'BL1',
    'ligue_1':           'FL1',
}


class SportsPredictor:
    """
    Ciph's demonic football prediction engine.
    
    5 layers:
    1. Math     — Poisson distribution + xG
    2. Market   — Odds movement, sharp money detection
    3. News     — Injuries, suspensions, context
    4. Ciph     — LLM reasoning over all layers
    5. Arbiter  — Normalized scoring, final conviction score
    
    Runs as background daemon — learns continuously.
    All AI dialogues logged and timestamped.
    """

    def __init__(self, vault: CipherVault):
        self.vault           = vault
        self.api_key         = vault.get_config('football_api_key') or ''
        self.headers         = {'X-Auth-Token': self.api_key} if self.api_key else {}
        self.weights         = self._load_weights()
        self.daemon_running  = False
        self.daemon_thread   = None
        self.monitored_leagues = self._load_monitored_leagues()
        # At the end of __init__, after loading weights, add:
        self.min_edge = float(self.vault.get_config('sports_min_edge') or 0.05)  # 5% minimum edge

        os.makedirs(LOGS_DIR,        exist_ok=True)
        os.makedirs(PREDICTIONS_DIR, exist_ok=True)

    # ─────────────────────────────────────────────
    # DAEMON — Background learning engine
    # ─────────────────────────────────────────────

    def start_daemon(self, leagues: Optional[List[str]] = None) -> str:
        if self.daemon_running:
            return "Sports daemon already running."

        if leagues:
            self.monitored_leagues = [l for l in leagues if l in LEAGUES]
            self._save_monitored_leagues()

        if not self.monitored_leagues:
            self.monitored_leagues = ['premier_league', 'champions_league']
            self._save_monitored_leagues()

        self.daemon_running = True
        self.daemon_thread  = threading.Thread(
            target=self._daemon_loop,
            daemon=True,
            name='CiphSportsDaemon'
        )
        self.daemon_thread.start()

        leagues_str = ', '.join(self.monitored_leagues)
        return (
            f"Sports daemon activated. Monitoring: {leagues_str}. "
            f"Pulling fixtures, odds, news in background. "
            f"Predictions improve over time automatically."
        )

    def stop_daemon(self) -> str:
        self.daemon_running = False
        return "Sports daemon stopped."

    def _daemon_loop(self):
        """Background loop — runs every 6 hours"""
        cycle = 0
        while self.daemon_running:
            try:
                print(f"\n[Sports Daemon] Cycle {cycle + 1} — {datetime.now().strftime('%H:%M')}")

                # Pull and cache fixtures
                for league in self.monitored_leagues:
                    fixtures = self._fetch_upcoming_fixtures(league)
                    if fixtures:
                        self._cache_fixtures(league, fixtures)
                        print(f"[Sports Daemon] {league}: {len(fixtures)} fixtures cached")

                # Check recent results and update weights
                self._update_weights_from_results()

                cycle += 1
                # Sleep 6 hours
                for _ in range(360):
                    if not self.daemon_running:
                        break
                    time.sleep(60)

            except Exception as e:
                print(f"[Sports Daemon] Error: {str(e)[:60]}")
                time.sleep(300)

    def set_min_edge(self, edge: float):
        """Set minimum edge for trade (e.g., 0.05 = 5%)."""
        self.min_edge = edge
        self.vault.set_config('sports_min_edge', str(edge))
        return f"Minimum edge set to {edge*100}%"



    def fetch_actual_result(self, home_team: str, away_team: str, match_date: str) -> Optional[str]:
        """Fetch the result of a single match from a specific date."""
        try:
            date_obj = datetime.strptime(match_date, '%Y-%m-%d')
        except ValueError:
            return None

        if not self.api_key:
            return None

        try:
            date_str = date_obj.strftime('%Y-%m-%d')
            resp = requests.get(
                f"{FOOTBALL_API}/matches",
                headers=self.headers,
                params={'dateFrom': date_str, 'dateTo': date_str},
                timeout=10
            )
            if resp.status_code != 200:
                return None

            matches = resp.json().get('matches', [])
            for match in matches:
                m_home = match.get('homeTeam', {}).get('name', '').lower()
                m_away = match.get('awayTeam', {}).get('name', '').lower()
                if (home_team.lower() in m_home or m_home in home_team.lower()) and \
                   (away_team.lower() in m_away or m_away in away_team.lower()):
                    score = match.get('score', {}).get('fullTime', {})
                    home_score = score.get('home')
                    away_score = score.get('away')
                    if home_score is None or away_score is None:
                        return None
                    if home_score > away_score:
                        return 'HOME WIN'
                    elif away_score > home_score:
                        return 'AWAY WIN'
                    else:
                        return 'DRAW'
            return None
        except Exception as e:
            return None



    def auto_resolve_predictions(self, days_back=7, verbose=False):
        """Scan prediction files and resolve those completed over 24 hours ago."""
        from datetime import datetime, timedelta

        # Only print if verbose flag is True
        if verbose:
            print("[Auto] Running daily prediction resolution...")

        for fname in os.listdir(PREDICTIONS_DIR):
            if not fname.endswith('.json'):
                continue
            file_path = os.path.join(PREDICTIONS_DIR, fname)
            with open(file_path, 'r') as f:
                pred = json.load(f)

            # Skip if already resolved
            if pred.get('actual_result') not in (None, 'PENDING'):
                continue

            pred_date_str = pred['predicted_at'].split('T')[0]
            try:
                pred_date = datetime.strptime(pred_date_str, '%Y-%m-%d')
            except ValueError:
                continue

            # Wait at least 24 hours before trying to resolve
            if datetime.now() - pred_date < timedelta(hours=24):
                continue

            home = pred['home_team']
            away = pred['away_team']
        
            # COMMENT OUT or REMOVE this line:
            # print(f"[Auto] Fetching result for {home} vs {away} on {pred_date.strftime('%Y-%m-%d')}")
        
            actual = self.fetch_actual_result(home, away, pred_date.strftime('%Y-%m-%d'))

            if actual:
                # Only print if verbose
                if verbose:
                    print(f"[Auto] Resolved {home} vs {away}: {actual}")
                self.update_weights_from_result(fname.replace('.json', ''), actual)


    def start_auto_learner(self):
        """Main loop for the background sports learner thread."""
        import time
        while True:
            try:
                self.auto_resolve_predictions()
                # Sleep for 24 hours
                time.sleep(86400)
            except Exception as e:
                print(f"[Auto-Learner] Error: {e}")
                time.sleep(3600)  # Wait an hour before retrying on error
    

    # ─────────────────────────────────────────────
    # LAYER 1 — MATH (Poisson + xG)
    # ─────────────────────────────────────────────

    def _math_layer(self, home_team: str, away_team: str,
                    home_stats: Dict, away_stats: Dict) -> Dict[str, Any]:
        """
        Poisson distribution prediction.
        Calculates exact scoreline probabilities.
        """
        import math

        # Get attack/defense strength
        home_attack  = home_stats.get('avg_goals_scored', 1.4)
        home_defense = home_stats.get('avg_goals_conceded', 1.2)
        away_attack  = away_stats.get('avg_goals_scored', 1.2)
        away_defense = away_stats.get('avg_goals_conceded', 1.4)

        # League averages (Premier League baseline)
        league_avg_home = 1.5
        league_avg_away = 1.1

        # Expected goals using attack/defense strength
        home_xg = (home_attack / league_avg_home) * (away_defense / league_avg_away) * league_avg_home
        away_xg = (away_attack / league_avg_away) * (home_defense / league_avg_home) * league_avg_away

        # Add home advantage
        home_xg *= 1.1

        # Poisson probabilities for scorelines 0-5
        def poisson_prob(lam, k):
            return (math.exp(-lam) * (lam ** k)) / math.factorial(k)

        home_probs = [poisson_prob(home_xg, i) for i in range(6)]
        away_probs = [poisson_prob(away_xg, i) for i in range(6)]

        # Calculate match outcome probabilities
        home_win = draw = away_win = 0
        scorelines = []

        for h in range(6):
            for a in range(6):
                prob = home_probs[h] * away_probs[a]
                scorelines.append({
                    'score': f"{h}-{a}",
                    'prob':  round(prob * 100, 2)
                })
                if h > a:   home_win += prob
                elif h == a: draw    += prob
                else:        away_win += prob

        # Sort scorelines by probability
        scorelines.sort(key=lambda x: x['prob'], reverse=True)

        # Over 2.5 and BTTS
        over_25 = sum(
            home_probs[h] * away_probs[a]
            for h in range(6) for a in range(6)
            if h + a > 2
        )
        btts = sum(
            home_probs[h] * away_probs[a]
            for h in range(1, 6) for a in range(1, 6)
        )

        # Normalize
        total    = home_win + draw + away_win
        home_win = home_win / total if total > 0 else 0.33
        draw     = draw     / total if total > 0 else 0.33
        away_win = away_win / total if total > 0 else 0.34

        # Confidence score 0-1
        max_prob   = max(home_win, draw, away_win)
        confidence = min(1.0, max_prob * 1.2)

        if home_win >= draw and home_win >= away_win:
            outcome = 'HOME WIN'
        elif away_win >= draw and away_win >= home_win:
            outcome = 'AWAY WIN'
        else:
            outcome = 'DRAW'

        return {
            'layer':        'math',
            'outcome':      outcome,
            'confidence':   round(confidence, 3),
            'home_win_pct': round(home_win * 100, 1),
            'draw_pct':     round(draw     * 100, 1),
            'away_win_pct': round(away_win * 100, 1),
            'home_xg':      round(home_xg,  2),
            'away_xg':      round(away_xg,  2),
            'over_25_pct':  round(over_25 * 100, 1),
            'btts_pct':     round(btts    * 100, 1),
            'top_scorelines': scorelines[:5],
            'raw_score':    confidence
        }

    # ─────────────────────────────────────────────
    # LAYER 2 — MARKET (Odds Movement)
    # ─────────────────────────────────────────────

    def _market_layer(self, home_team: str, away_team: str) -> Dict[str, Any]:
        """
        Detect sharp money movement in odds.
        Sharp movement = odds shift without public reason = insider confidence.
        """
        # Try to get odds from free source
        odds_data = self._fetch_odds(home_team, away_team)

        if not odds_data:
            return {
                'layer':      'market',
                'available':  False,
                'confidence': 0.5,
                'raw_score':  0.5,
                'signal':     'NO_DATA'
            }

        current_home = odds_data.get('home_odds', 2.0)
        current_draw = odds_data.get('draw_odds', 3.2)
        current_away = odds_data.get('away_odds', 3.5)
        open_home    = odds_data.get('open_home',  current_home)
        open_away    = odds_data.get('open_away',  current_away)

        # Implied probabilities
        home_implied = 1 / current_home if current_home > 0 else 0.33
        draw_implied = 1 / current_draw if current_draw > 0 else 0.33
        away_implied = 1 / current_away if current_away > 0 else 0.34

        # Normalize
        total        = home_implied + draw_implied + away_implied
        home_implied = home_implied / total
        away_implied = away_implied / total
        draw_implied = draw_implied / total

        # Detect movement
        home_movement = ((open_home - current_home) / open_home) if open_home > 0 else 0
        away_movement = ((open_away - current_away) / open_away) if open_away > 0 else 0

        # Sharp signal
        sharp_signal  = 'NEUTRAL'
        sharp_score   = 0.5

        if abs(home_movement) > 0.05:
            if home_movement > 0:
                sharp_signal = 'SHARP_HOME'
                sharp_score  = min(0.9, 0.5 + home_movement * 2)
            else:
                sharp_signal = 'SHARP_AWAY'
                sharp_score  = min(0.9, 0.5 + abs(away_movement) * 2)

        if home_implied >= away_implied and home_implied >= draw_implied:
            outcome = 'HOME WIN'
            confidence = home_implied
        elif away_implied >= home_implied and away_implied >= draw_implied:
            outcome = 'AWAY WIN'
            confidence = away_implied
        else:
            outcome = 'DRAW'
            confidence = draw_implied

        # If sharp money detected — boost confidence
        if sharp_signal != 'NEUTRAL':
            confidence = min(0.9, confidence * 1.2)

        return {
            'layer':        'market',
            'available':    True,
            'outcome':      outcome,
            'confidence':   round(confidence, 3),
            'home_win_pct': round(home_implied * 100, 1),
            'draw_pct':     round(draw_implied * 100, 1),
            'away_win_pct': round(away_implied * 100, 1),
            'sharp_signal': sharp_signal,
            'home_odds':    current_home,
            'away_odds':    current_away,
            'raw_score':    round(sharp_score, 3)
        }

    def _fetch_odds(self, home_team: str, away_team: str) -> Optional[Dict]:
        """Fetch odds from free source"""
        try:
            resp = requests.get(
                "https://api.the-odds-api.com/v4/sports/soccer_epl/odds",
                params={
                    'apiKey':  self.vault.get_config('odds_api_key') or '',
                    'regions': 'uk',
                    'markets': 'h2h',
                },
                timeout=10
            )
            if resp.status_code != 200:
                return None

            for game in resp.json():
                if (home_team.lower() in game['home_team'].lower() or
                    away_team.lower() in game['away_team'].lower()):
                    bookmakers = game.get('bookmakers', [])
                    if bookmakers:
                        outcomes = bookmakers[0]['markets'][0]['outcomes']
                        odds_map = {o['name'].lower(): o['price'] for o in outcomes}
                        return {
                            'home_odds': odds_map.get(home_team.lower(), 2.0),
                            'away_odds': odds_map.get(away_team.lower(), 3.5),
                            'draw_odds': odds_map.get('draw', 3.2),
                        }
        except Exception:
            pass
        return None

    # ─────────────────────────────────────────────
    # LAYER 3 — NEWS (Context Intelligence)
    # ─────────────────────────────────────────────

    def _news_layer(self, home_team: str, away_team: str) -> Dict[str, Any]:
        """
        Scrape sports news for context.
        Detects injuries, suspensions, motivation factors.
        """
        news_items = []
        impact_score = 0.0

        try:
            import feedparser
            feeds = [
                f"https://www.skysports.com/rss/12040",
                f"https://www.bbc.co.uk/sport/football/rss.xml",
                f"https://feeds.bbci.co.uk/sport/football/rss.xml",
            ]

            negative_keywords = [
                'injured', 'injury', 'suspended', 'suspension',
                'ruled out', 'doubt', 'miss', 'absent', 'crisis'
            ]
            positive_keywords = [
                'returns', 'fit', 'available', 'boost',
                'confident', 'winning run', 'unbeaten'
            ]

            for feed_url in feeds:
                try:
                    feed = feedparser.parse(feed_url)
                    for entry in feed.entries[:20]:
                        title   = str(entry.get('title', '') or '').lower()
                        summary = str(entry.get('summary', '') or '').lower()
                        content = title + ' ' + summary

                        home_mentioned = home_team.lower() in content
                        away_mentioned = away_team.lower() in content

                        if not (home_mentioned or away_mentioned):
                            continue

                        # Detect sentiment
                        neg_hits = sum(1 for k in negative_keywords if k in content)
                        pos_hits = sum(1 for k in positive_keywords if k in content)

                        if neg_hits > 0 or pos_hits > 0:
                            team    = home_team if home_mentioned else away_team
                            sentiment = 'NEGATIVE' if neg_hits > pos_hits else 'POSITIVE'
                            impact  = -0.1 * neg_hits if sentiment == 'NEGATIVE' else 0.05 * pos_hits

                            if home_mentioned:
                                impact_score += impact
                            else:
                                impact_score -= impact

                            news_items.append({
                                'team':      team,
                                'headline':  entry.get('title', ''),
                                'sentiment': sentiment,
                                'impact':    round(impact, 2)
                            })
                except Exception:
                    continue

        except ImportError:
            pass

        # Normalize impact to -1 to 1
        impact_score = max(-0.5, min(0.5, impact_score))

        # Convert to confidence adjustment
        raw_score = 0.5 + impact_score

        return {
            'layer':        'news',
            'news_items':   news_items[:5],
            'impact_score': round(impact_score, 3),
            'raw_score':    round(raw_score,    3),
            'summary':      f"{len(news_items)} relevant articles found"
        }

    # ─────────────────────────────────────────────
    # LAYER 4 — CIPH REASONING
    # ─────────────────────────────────────────────

    def _ciph_layer(self, home_team: str, away_team: str,
                    math_result: Dict, market_result: Dict,
                    news_result: Dict, match_id: str) -> Dict[str, Any]:
        """
        Ciph reasons over all previous layers.
        Outputs structured prediction with confidence.
        All dialogue logged and timestamped.
        """
        # Build context for Ciph
        context = f"""You are analyzing a football match for prediction purposes.

MATCH: {home_team} vs {away_team}
DATE: {datetime.now().strftime('%d %b %Y')}

MATH LAYER (Poisson + xG):
- Predicted outcome: {math_result.get('outcome', 'N/A')}
- Home win: {math_result.get('home_win_pct', 'N/A')}%
- Draw: {math_result.get('draw_pct', 'N/A')}%  
- Away win: {math_result.get('away_win_pct', 'N/A')}%
- Home xG: {math_result.get('home_xg', 'N/A')}
- Away xG: {math_result.get('away_xg', 'N/A')}
- Top scoreline: {math_result.get('top_scorelines', [{}])[0].get('score', 'N/A')}

MARKET LAYER (Odds Movement):
- Sharp signal: {market_result.get('sharp_signal', 'NO_DATA')}
- Market prediction: {market_result.get('outcome', 'N/A')}
- Home odds: {market_result.get('home_odds', 'N/A')}
- Away odds: {market_result.get('away_odds', 'N/A')}

NEWS LAYER:
- {news_result.get('summary', 'No news data')}
- Key items: {json.dumps([n['headline'] for n in news_result.get('news_items', [])[:3]])}

Based on ALL of this data, provide your prediction in this EXACT JSON format:
{{
  "outcome": "HOME WIN or DRAW or AWAY WIN",
  "confidence": 0.0 to 1.0,
  "over_25": 0.0 to 1.0,
  "btts": 0.0 to 1.0,
  "key_factors": ["factor 1", "factor 2", "factor 3"],
  "contrarian": true or false,
  "contrarian_reason": "explain if your prediction differs from math/market",
  "reasoning": "2-3 sentence explanation"
}}

Respond with ONLY the JSON. No other text."""

        # Log the dialogue
        log_entry = {
            'match_id':   match_id,
            'timestamp':  datetime.now().isoformat(),
            'type':       'ciph_reasoning_request',
            'home_team':  home_team,
            'away_team':  away_team,
            'prompt':     context,
            'math_says':  math_result.get('outcome'),
            'market_says': market_result.get('outcome'),
        }

        try:
            payload = {
                "model":    OLLAMA_MODEL,
                "messages": [
                    {
                        "role":    "system",
                        "content": "You are Ciph, a football prediction intelligence. You analyze data and output precise JSON predictions. Never output anything except valid JSON."
                    },
                    {
                        "role":    "user",
                        "content": context
                    }
                ],
                "stream":      False,
                "temperature": 0.2,
            }

            resp = requests.post(PROXY_URL, json=payload, timeout=120)
            resp.raise_for_status()

            raw_response = resp.json()["message"]["content"].strip()

            # Strip any markdown
            raw_response = raw_response.replace("```json", "").replace("```", "").strip()
            
            #Robust JSON extraction
            import re 
            match = re.search(r'\{.*\}', raw_response, re.DOTALL)
            if match:
                ciph_prediction = json.loads(match.group(0))
            else:
                print(f"[Ciph Layer] Raw response: {raw_response[:200]}")
                raise ValueError("No valid JSON in response")

            # Log the response
            log_entry['response']      = raw_response
            log_entry['ciph_outcome']  = ciph_prediction.get('outcome')
            log_entry['ciph_confidence'] = ciph_prediction.get('confidence')
            log_entry['contrarian']    = ciph_prediction.get('contrarian', False)
            log_entry['status']        = 'success'

            self._log_dialogue(match_id, log_entry)

            return {
                'layer':             'ciph',
                'outcome':           ciph_prediction.get('outcome', 'HOME WIN'),
                'confidence':        float(ciph_prediction.get('confidence', 0.5)),
                'over_25':           float(ciph_prediction.get('over_25',    0.5)),
                'btts':              float(ciph_prediction.get('btts',       0.5)),
                'key_factors':       ciph_prediction.get('key_factors',      []),
                'contrarian':        ciph_prediction.get('contrarian',       False),
                'contrarian_reason': ciph_prediction.get('contrarian_reason', ''),
                'reasoning':         ciph_prediction.get('reasoning',        ''),
                'raw_score':         float(ciph_prediction.get('confidence', 0.5)),
                'raw_response':      raw_response
            }

        except Exception as e:
            log_entry['status'] = 'failed'
            log_entry['error']  = str(e)
            self._log_dialogue(match_id, log_entry)

            return {
                'layer':      'ciph',
                'outcome':    math_result.get('outcome', 'HOME WIN'),
                'confidence': 0.5,
                'raw_score':  0.5,
                'error':      str(e)[:60]
            }

    # ─────────────────────────────────────────────
    # LAYER 5 — ARBITER (Normalized Scoring)
    # ─────────────────────────────────────────────

    def _arbiter(self, home_team: str, away_team: str,
                 math_r: Dict, market_r: Dict,
                 news_r: Dict, ciph_r: Dict) -> Dict[str, Any]:
        """
        Normalize all layers to same scale.
        Calculate weighted conviction score.
        Detect contrarian signals.
        """
        weights = self.weights

        # Convert outcomes to numeric scores
        def outcome_to_score(result: Dict) -> Tuple[float, float, float]:
            outcome = result.get('outcome', 'HOME WIN')
            conf    = result.get('confidence', result.get('raw_score', 0.5))
            if outcome == 'HOME WIN':
                return conf, (1 - conf) * 0.4, (1 - conf) * 0.6
            elif outcome == 'AWAY WIN':
                return (1 - conf) * 0.6, (1 - conf) * 0.4, conf
            else:
                return (1 - conf) * 0.5, conf, (1 - conf) * 0.5

        math_h,   math_d,   math_a   = outcome_to_score(math_r)
        market_h, market_d, market_a = outcome_to_score(market_r) if market_r.get('available') else (0.33, 0.33, 0.34)
        news_adj                      = news_r.get('impact_score', 0)
        ciph_h,   ciph_d,   ciph_a   = outcome_to_score(ciph_r)

        # Market weight boost if sharp signal detected
        market_weight = weights['market']
        if market_r.get('sharp_signal') not in ('NEUTRAL', 'NO_DATA', None):
            market_weight = min(0.45, market_weight * 1.5)

        # Weighted final scores
        w_math   = weights['math']
        w_news   = weights['news']
        w_ciph   = weights['ciph']

        # Renormalize weights
        total_w  = w_math + market_weight + w_news + w_ciph
        w_math   = w_math   / total_w
        w_mkt    = market_weight / total_w
        w_news_n = w_news   / total_w
        w_ciph_n = w_ciph   / total_w

        final_home = (w_math * math_h + w_mkt * market_h +
                      w_news_n * (0.33 + news_adj) + w_ciph_n * ciph_h)
        final_draw = (w_math * math_d + w_mkt * market_d +
                      w_news_n * 0.33 + w_ciph_n * ciph_d)
        final_away = (w_math * math_a + w_mkt * market_a +
                      w_news_n * (0.33 - news_adj) + w_ciph_n * ciph_a)
        
        # Normalize to sum to 1
        total      = final_home + final_draw + final_away
        final_home = final_home / total if total > 0 else 0.33
        final_draw = final_draw / total if total > 0 else 0.33
        final_away = final_away / total if total > 0 else 0.34
      
        
        # ========== INSERT EDGE CALCULATION HERE ==========
        # Get market implied probabilities (from market layer)
        market_home = market_r.get('home_win_pct', 33.3) / 100.0
        market_draw = market_r.get('draw_pct', 33.3) / 100.0
        market_away = market_r.get('away_win_pct', 33.4) / 100.0

        # Determine Ciph's most likely outcome and its probability
        ciph_probs = {'HOME WIN': final_home, 'DRAW': final_draw, 'AWAY WIN': final_away}
        ciph_outcome = max(ciph_probs, key=ciph_probs.get)
        ciph_prob = ciph_probs[ciph_outcome]

        # Corresponding market probability
        market_prob = {
            'HOME WIN': market_home,
            'DRAW': market_draw,
            'AWAY WIN': market_away
        }[ciph_outcome]

        # Calculate edge
        edge = ciph_prob - market_prob

        # Trade decision
        min_edge = getattr(self, 'min_edge', 0.05)
        if edge >= min_edge:
            trade_decision = 'TRADE'
            trade_reason = f'Edge: {edge:.1%}'
        else:
            trade_decision = 'NO_TRADE'
            trade_reason = f'Edge too small: {edge:.1%} (need {min_edge:.0%})'
        # ========== END EDGE CALCULATION ==========


        # Final outcome
        if final_home >= final_draw and final_home >= final_away:
            final_outcome = 'HOME WIN'
            conviction    = final_home
        elif final_away >= final_draw and final_away >= final_home:
            final_outcome = 'AWAY WIN'
            conviction    = final_away
        else:
            final_outcome = 'DRAW'
            conviction    = final_draw

        # Detect contrarian signal
        outcomes   = [math_r.get('outcome'), market_r.get('outcome'), ciph_r.get('outcome')]
        outcomes   = [o for o in outcomes if o]
        is_contrarian = len(set(outcomes)) > 1

        # Rating
        if conviction >= 0.65:   rating = 'HIGH'
        elif conviction >= 0.50: rating = 'MEDIUM'
        else:                    rating = 'LOW'

        # Over 2.5 and BTTS (weighted average)
        over_25 = (w_math * math_r.get('over_25_pct', 50) / 100 +
                   w_ciph_n * ciph_r.get('over_25', 0.5))
        btts    = (w_math * math_r.get('btts_pct', 40) / 100 +
                   w_ciph_n * ciph_r.get('btts', 0.4))

        return {
            'final_outcome':  final_outcome,
            'conviction':     round(conviction, 3),
            'rating':         rating,
            'home_win_pct':   round(final_home * 100, 1),
            'draw_pct':       round(final_draw * 100, 1),
            'away_win_pct':   round(final_away * 100, 1),
            'over_25_pct':    round(over_25 * 100,    1),
            'btts_pct':       round(btts    * 100,    1),
            'is_contrarian':  is_contrarian,
            'layer_verdicts': {
                'math':   math_r.get('outcome'),
                'market': market_r.get('outcome'),
                'ciph':   ciph_r.get('outcome')
            },
            'weights_used':   {
                'math':   round(w_math,   2),
                'market': round(w_mkt,    2),
                'news':   round(w_news_n, 2),
                'ciph':   round(w_ciph_n, 2)
            },
            # NEW FIELDS:
            'trade_decision': trade_decision,
            'trade_reason': trade_reason,
            'ciph_probability': ciph_prob,
            'market_probability': market_prob,
            'edge': edge
        }

    # ─────────────────────────────────────────────
    # MAIN PREDICTION ENTRY POINT
    # ─────────────────────────────────────────────

    def predict_match(self, home_team: str, away_team: str) -> Dict[str, Any]:
        """
        Full 5-layer prediction for a match.
        """
        match_id = hashlib.md5(
            f"{home_team}{away_team}{datetime.now().date()}".encode()
        ).hexdigest()[:10]

        print(f"\n[Ciph Sports] Analyzing: {home_team} vs {away_team}")

        # Get team stats
        home_stats = self._get_team_stats(home_team)
        away_stats = self._get_team_stats(away_team)

        # Run all layers
        print("  [1/4] Math layer (Poisson + xG)...")
        math_result = self._math_layer(home_team, away_team, home_stats, away_stats)

        print("  [2/4] Market layer (Odds movement)...")
        market_result = self._market_layer(home_team, away_team)

        print("  [3/4] News layer (Context)...")
        news_result = self._news_layer(home_team, away_team)

        print("  [4/4] Ciph reasoning layer...")
        ciph_result = self._ciph_layer(
            home_team, away_team,
            math_result, market_result, news_result,
            match_id
        )

        print("  [5/5] Arbiter calculating conviction...")
        arbiter_result = self._arbiter(
            home_team, away_team,
            math_result, market_result, news_result, ciph_result
        )

        # Full prediction package
        prediction = {
            'match_id':    match_id,
            'home_team':   home_team,
            'away_team':   away_team,
            'predicted_at': datetime.now().isoformat(),
            'layers': {
                'math':    math_result,
                'market':  market_result,
                'news':    news_result,
                'ciph':    ciph_result,
                'arbiter': arbiter_result
            },
            'final': arbiter_result,
            'signal': self._format_signal(home_team, away_team, arbiter_result, ciph_result, math_result)
        }

        # Check 10 prediction email trigger
        if hasattr(self, 'performance') and self.performance.check_10_prediction_trigger():
            self.performance.send_report(trigger='10-predictions')

        # Save prediction
        self._save_prediction(match_id, prediction)

        return prediction

        
    def predict_today(self) -> str:
        """Predict all matches today across monitored leagues"""
        today    = datetime.now().strftime('%Y-%m-%d')
        all_predictions = []

        for league in self.monitored_leagues:
            fixtures = self._get_cached_fixtures(league)
            today_fixtures = [f for f in fixtures if f.get('date', '') == today]

            for fix in today_fixtures:
                pred = self.predict_match(fix['home'], fix['away'])
                all_predictions.append(pred['signal'])

        if not all_predictions:
            # Check tomorrow
            tomorrow = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
            for league in self.monitored_leagues:
                fixtures = self._get_cached_fixtures(league)
                tomorrow_fixtures = [f for f in fixtures if f.get('date', '') == tomorrow]
                if tomorrow_fixtures:
                    return f"No matches today. Next matches tomorrow ({tomorrow}): " + \
                           ', '.join([f"{f['home']} vs {f['away']}" for f in tomorrow_fixtures[:3]])
            return "No matches today or tomorrow in monitored leagues."

        header = f"CIPH PREDICTIONS — {today}\n{'='*50}\n"
        return header + '\n\n'.join(all_predictions)

    # ─────────────────────────────────────────────
    # SIGNAL FORMATTING
    # ─────────────────────────────────────────────

    def _format_signal(self, home: str, away: str,
                       arbiter: Dict, ciph: Dict, math: Dict) -> str:
        # If NO_TRADE, return a different message
        if arbiter.get('trade_decision') == 'NO_TRADE':
            edge = arbiter.get('edge', 0)
            min_edge = getattr(self, 'min_edge', 0.05)
            return f"""
⚠️ NO TRADE RECOMMENDED
Match: {home} vs {away}
Ciph probability: {arbiter.get('ciph_probability', 0)*100:.1f}%
Market implied: {arbiter.get('market_probability', 0)*100:.1f}%
Edge: {edge*100:.1f}% (minimum required: {min_edge*100:.0f}%)
Reason: {arbiter.get('trade_reason', 'Insufficient edge')}

No action suggested. Wait for higher confidence opportunity.
"""
        rating_emoji = {'HIGH': '🟢', 'MEDIUM': '🟡', 'LOW': '🔴'}.get(arbiter['rating'], '⚪')
        contrarian   = "⚡ CONTRARIAN SIGNAL" if arbiter['is_contrarian'] else ""

        layer_agrees = ""
        verdicts     = arbiter.get('layer_verdicts', {})
        for layer, verdict in verdicts.items():
            if verdict:
                layer_agrees += f"\n    {layer.upper()}: {verdict}"

        key_factors = ""
        for factor in ciph.get('key_factors', [])[:3]:
            key_factors += f"\n  • {factor}"

        signal = f"""
⚽ CIPH INTELLIGENCE — {datetime.now().strftime('%d %b %Y')}
{'='*45}
{home} vs {away}

🎯 PREDICTION: {arbiter['final_outcome']}
{rating_emoji} CONVICTION: {round(arbiter['conviction'] * 100)}% [{arbiter['rating']}]
{contrarian}

📊 PROBABILITIES:
  Home Win : {arbiter['home_win_pct']}%
  Draw     : {arbiter['draw_pct']}%
  Away Win : {arbiter['away_win_pct']}%

⚡ MARKETS:
  Over 2.5 Goals  : {arbiter['over_25_pct']}%
  Both Teams Score: {arbiter['btts_pct']}%
  Top Scoreline   : {math.get('top_scorelines', [{}])[0].get('score', 'N/A')}

🧠 LAYER VERDICTS:{layer_agrees}

💡 KEY FACTORS:{key_factors if key_factors else chr(10) + '  No key factors'}

📝 CIPH REASONING:
  {ciph.get('reasoning', 'N/A')}

—
🔒 Powered by Ciph Intelligence Engine
"""
        return signal.strip()

    # ─────────────────────────────────────────────
    # LEARNING — Update weights from results
    # ─────────────────────────────────────────────

    def record_result(self, match_id: str, actual_result: str) -> str:
        """
        Record actual match result.
        Updates layer weights based on which layers were right.
        """
        pred_file = os.path.join(PREDICTIONS_DIR, f"{match_id}.json")
        if not os.path.exists(pred_file):
            return f"Prediction {match_id} not found."

        with open(pred_file, 'r') as f:
            prediction = json.load(f)

        layers  = prediction.get('layers', {})
        correct = {}

        for layer_name in ['math', 'market', 'ciph']:
            layer_pred = layers.get(layer_name, {}).get('outcome')
            if layer_pred:
                correct[layer_name] = (layer_pred == actual_result.upper())

        # Update weights — increase weight of correct layers
        for layer, was_correct in correct.items():
            if was_correct:
                self.weights[layer] = min(0.6, self.weights[layer] * 1.05)
            else:
                self.weights[layer] = max(0.1, self.weights[layer] * 0.95)

        # Renormalize
        total = sum(self.weights.values())
        for k in self.weights:
            self.weights[k] = round(self.weights[k] / total, 3)

        self._save_weights()

        # Log result
        prediction['actual_result'] = actual_result.upper()
        prediction['result_logged'] = datetime.now().isoformat()
        prediction['layer_correct'] = correct

        with open(pred_file, 'w') as f:
            json.dump(prediction, f, indent=2)

        correct_layers = [l for l, c in correct.items() if c]
        return (
            f"Result recorded: {actual_result.upper()}. "
            f"Correct layers: {', '.join(correct_layers) if correct_layers else 'none'}. "
            f"Weights updated: {json.dumps(self.weights)}"
        )

    def _update_weights_from_results(self):
        """Background weight updates from stored results"""
        pass

    # ─────────────────────────────────────────────
    # DATA HELPERS
    # ─────────────────────────────────────────────

    def _get_team_stats(self, team: str) -> Dict[str, Any]:
        """Get team stats from API or cache"""
        cache_key = f"team_stats_{hashlib.md5(team.encode()).hexdigest()[:8]}"
        cached    = self.vault.get_config(cache_key)

        if cached:
            try:
                data = json.loads(cached)
                if data.get('cached_at', '') > (datetime.now() - timedelta(days=1)).isoformat():
                    return data
            except Exception:
                pass

        if not self.api_key:
            return {
                'team':               team,
                'avg_goals_scored':   1.4,
                'avg_goals_conceded': 1.2,
                'form':               'UNKNOWN',
                'data_source':        'default'
            }

        try:
            resp = requests.get(
                f"{FOOTBALL_API}/teams",
                headers=self.headers,
                params={'name': team},
                timeout=10
            )
            if resp.status_code != 200:
                return {'team': team, 'avg_goals_scored': 1.4, 'avg_goals_conceded': 1.2}

            teams = resp.json().get('teams', [])
            if not teams:
                return {'team': team, 'avg_goals_scored': 1.4, 'avg_goals_conceded': 1.2}

            team_id = teams[0]['id']

            resp = requests.get(
                f"{FOOTBALL_API}/teams/{team_id}/matches",
                headers=self.headers,
                params={'status': 'FINISHED', 'limit': 10},
                timeout=10
            )

            matches   = resp.json().get('matches', [])
            goals_for = goals_ag = 0

            for match in matches[-10:]:
                is_home = match['homeTeam']['id'] == team_id
                hg      = match['score']['fullTime']['home'] or 0
                ag      = match['score']['fullTime']['away'] or 0
                if is_home:
                    goals_for += hg; goals_ag += ag
                else:
                    goals_for += ag; goals_ag += hg

            n = len(matches) or 1

            stats = {
                'team':               team,
                'avg_goals_scored':   round(goals_for / n, 2),
                'avg_goals_conceded': round(goals_ag  / n, 2),
                'games_analyzed':     n,
                'data_source':        'football_data_org',
                'cached_at':          datetime.now().isoformat()
            }

            self.vault.set_config(cache_key, json.dumps(stats))
            return stats

        except Exception as e:
            return {'team': team, 'avg_goals_scored': 1.4, 'avg_goals_conceded': 1.2}

    def _fetch_upcoming_fixtures(self, league: str) -> List[Dict]:
        """Fetch upcoming fixtures from API"""
        if not self.api_key:
            return []

        league_code = LEAGUES.get(league, 'PL')
        date_from   = datetime.now().strftime('%Y-%m-%d')
        date_to     = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')

        try:
            resp = requests.get(
                f"{FOOTBALL_API}/competitions/{league_code}/matches",
                headers=self.headers,
                params={'status': 'SCHEDULED', 'dateFrom': date_from, 'dateTo': date_to},
                timeout=10
            )
            if resp.status_code != 200:
                return []

            fixtures = []
            for match in resp.json().get('matches', []):
                fixtures.append({
                    'home': match['homeTeam']['name'],
                    'away': match['awayTeam']['name'],
                    'date': match['utcDate'][:10],
                })
            return fixtures

        except Exception:
            return []

    def _cache_fixtures(self, league: str, fixtures: List[Dict]):
        key = f"fixtures_{league}_{datetime.now().strftime('%Y%m%d')}"
        self.vault.set_config(key, json.dumps(fixtures))

    def _get_cached_fixtures(self, league: str) -> List[Dict]:
        key    = f"fixtures_{league}_{datetime.now().strftime('%Y%m%d')}"
        cached = self.vault.get_config(key)
        if cached:
            try:
                return json.loads(cached)
            except Exception:
                pass
        return []

    def _save_prediction(self, match_id: str, prediction: Dict):
        path = os.path.join(PREDICTIONS_DIR, f"{match_id}.json")
        with open(path, 'w') as f:
            json.dump(prediction, f, indent=2)

    def _log_dialogue(self, match_id: str, entry: Dict):
        """Save AI dialogue to timestamped log file"""
        log_file = os.path.join(LOGS_DIR, f"dialogue_{match_id}.json")
        logs     = []

        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            except Exception:
                logs = []

        logs.append(entry)

        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)

    # ─────────────────────────────────────────────
    # WEIGHT PERSISTENCE
    # ─────────────────────────────────────────────

    def _load_weights(self) -> Dict[str, float]:
        raw = self.vault.get_config('sports_weights')
        if raw:
            try:
                return json.loads(raw)
            except Exception:
                pass
        return DEFAULT_WEIGHTS.copy()

    def _save_weights(self):
        self.vault.set_config('sports_weights', json.dumps(self.weights))

    def _load_monitored_leagues(self) -> List[str]:
        raw = self.vault.get_config('sports_leagues')
        if raw:
            try:
                return json.loads(raw)
            except Exception:
                pass
        return ['premier_league', 'champions_league']

    def _save_monitored_leagues(self):
        self.vault.set_config('sports_leagues', json.dumps(self.monitored_leagues))

    # ─────────────────────────────────────────────
    # SETUP AND STATUS
    # ─────────────────────────────────────────────

    def set_api_key(self, key: str) -> str:
        self.api_key = key
        self.headers = {'X-Auth-Token': key}
        self.vault.set_config('football_api_key', key)
        return "Football API key saved permanently. Predictions now data-driven."

    def get_status(self) -> Dict[str, Any]:
        return {
            'daemon_running':    self.daemon_running,
            'api_configured':    bool(self.api_key),
            'monitored_leagues': self.monitored_leagues,
            'current_weights':   self.weights,
            'predictions_made':  len(os.listdir(PREDICTIONS_DIR)),
            'dialogues_logged':  len(os.listdir(LOGS_DIR)),
            'status':            'ACTIVE' if self.daemon_running else 'STANDBY'
        }

    def view_dialogue(self, match_id: str) -> str:
        """View the AI dialogue for a specific prediction"""
        log_file = os.path.join(LOGS_DIR, f"dialogue_{match_id}.json")
        if not os.path.exists(log_file):
            return f"No dialogue found for match {match_id}"

        with open(log_file, 'r') as f:
            logs = json.load(f)

        output = [f"AI DIALOGUE LOG — Match {match_id}\n{'='*50}"]
        for entry in logs:
            output.append(f"\nTimestamp: {entry.get('timestamp', 'N/A')}")
            output.append(f"Type: {entry.get('type', 'N/A')}")
            output.append(f"Math says: {entry.get('math_says', 'N/A')}")
            output.append(f"Market says: {entry.get('market_says', 'N/A')}")
            output.append(f"Ciph says: {entry.get('ciph_outcome', 'N/A')}")
            output.append(f"Confidence: {entry.get('ciph_confidence', 'N/A')}")
            output.append(f"Status: {entry.get('status', 'N/A')}")
            if entry.get('contrarian'):
                output.append(f"CONTRARIAN: Yes")
            output.append("-" * 30)

        return '\n'.join(output)

    def list_predictions(self) -> str:
        """List all stored predictions"""
        files = os.listdir(PREDICTIONS_DIR)
        if not files:
            return "No predictions stored yet."

        output = [f"Stored predictions: {len(files)}\n"]
        for fname in sorted(files)[-10:]:
            match_id = fname.replace('.json', '')
            path     = os.path.join(PREDICTIONS_DIR, fname)
            try:
                with open(path, 'r') as f:
                    pred = json.load(f)
                home   = pred.get('home_team', 'N/A')
                away   = pred.get('away_team', 'N/A')
                result = pred.get('final', {}).get('final_outcome', 'N/A')
                actual = pred.get('actual_result', 'PENDING')
                output.append(f"  {match_id}: {home} vs {away} → {result} | Actual: {actual}")
            except Exception:
                output.append(f"  {match_id}: [error reading]")

        return '\n'.join(output)


if __name__ == "__main__":
    from cipher_vault import CipherVault
    vault     = CipherVault()
    predictor = SportsPredictor(vault)
    print("Ciph Sports Engine ready.")
    print(json.dumps(predictor.get_status(), indent=2))
    print("\nGet free API key: https://www.football-data.org/client/register")
    print("Then: /set-football-api YOUR_KEY")
    print("Then: /sports-mode on")
    print("Then: /predict Arsenal vs Chelsea")