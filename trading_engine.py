#!/usr/bin/env python3
# trading_engine.py - Automated Crypto Trading & Portfolio Management

import requests
import time
import json
import hashlib
import hmac
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from cipher_vault import CipherVault

class TradingEngine:
    """
    Automated cryptocurrency trading and portfolio management
    Monitors markets, executes trades, and manages wealth
    """
    
    def __init__(self, vault: CipherVault):
        self.vault = vault
        self.portfolio = self._load_portfolio()
        self.trading_pairs = ['BTC-USDT', 'ETH-USDT', 'XMR-USDT', 'SOL-USDT']
        self.exchange_apis = {
            'binance': 'https://api.binance.com/api/v3',
            'coinbase': 'https://api.coinbase.com/v2',
            'kraken': 'https://api.kraken.com/0/public'
        }
        
    def _load_portfolio(self) -> Dict[str, Any]:
        """Load portfolio from encrypted vault"""
        portfolio_data = self.vault.get_config("trading_portfolio")
        if portfolio_data:
            try:
                return json.loads(portfolio_data)
            except Exception:
                pass
        
        # Default portfolio structure
        return {
            'total_value': 0,
            'assets': {},
            'trading_history': [],
            'performance': {
                'daily_change': 0,
                'total_profit': 0,
                'win_rate': 0
            },
            'risk_level': 'MODERATE',
            'last_updated': datetime.now().isoformat()
        }
    
    def _save_portfolio(self):
        """Save portfolio to encrypted vault"""
        self.portfolio['last_updated'] = datetime.now().isoformat()
        self.vault.set_config("trading_portfolio", json.dumps(self.portfolio))
    
    def get_market_data(self, symbol: str = 'BTCUSDT') -> Dict[str, Any]:
        """Get real-time market data from exchanges"""
        try:
            # Binance API for price data
            url = f"{self.exchange_apis['binance']}/ticker/24hr?symbol={symbol}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'symbol': symbol,
                    'price': float(data['lastPrice']),
                    'change_24h': float(data['priceChangePercent']),
                    'volume': float(data['volume']),
                    'high_24h': float(data['highPrice']),
                    'low_24h': float(data['lowPrice']),
                    'timestamp': datetime.now().isoformat()
                }
        except Exception as e:
            print(f"❌ Market data error: {e}")
        
        return {}
    
    def scan_arbitrage_opportunities(self) -> List[Dict[str, Any]]:
        """Scan for crypto arbitrage opportunities across exchanges"""
        print("🔍 Scanning arbitrage opportunities...")
        opportunities = []
        
        for pair in self.trading_pairs:
            try:
                # Get prices from multiple exchanges
                binance_price = self._get_binance_price(pair)
                kraken_price = self._get_kraken_price(pair)
                
                if binance_price and kraken_price:
                    price_diff = abs(binance_price - kraken_price)
                    diff_percent = (price_diff / min(binance_price, kraken_price)) * 100
                    
                    if diff_percent > 0.5:  # 0.5% threshold for arbitrage
                        opportunity = {
                            'pair': pair,
                            'binance_price': binance_price,
                            'kraken_price': kraken_price,
                            'price_difference': price_diff,
                            'difference_percent': diff_percent,
                            'potential_profit': f"${price_diff:.2f} per coin",
                            'timestamp': datetime.now().isoformat()
                        }
                        opportunities.append(opportunity)
                        
            except Exception as e:
                print(f"❌ Arbitrage scan error for {pair}: {e}")
        
        # Store opportunities in vault
        if opportunities:
            self.vault.store_conversation(
                "ARBITRAGE_OPPORTUNITIES",
                f"Found {len(opportunities)} arbitrage opportunities",
                "trading"
            )
        
        return opportunities
    
    def _get_binance_price(self, pair: str) -> Optional[float]:
        """Get price from Binance"""
        try:
            symbol = pair.replace('-', '')
            url = f"{self.exchange_apis['binance']}/ticker/price?symbol={symbol}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return float(response.json()['price'])
        except Exception:
            pass
        return None
    
    def _get_kraken_price(self, pair: str) -> Optional[float]:
        """Get price from Kraken"""
        try:
            kraken_pair = pair.replace('-', '').replace('USDT', 'USD')
            url = f"{self.exchange_apis['kraken']}/Ticker?pair={kraken_pair}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                # Kraken returns nested data structure
                for key in data['result']:
                    return float(data['result'][key]['c'][0])
        except Exception:
            pass
        return None
    
    def analyze_market_trends(self) -> Dict[str, Any]:
        """Analyze market trends and generate trading signals"""
        print("📈 Analyzing market trends...")
        trends = {}
        
        for pair in self.trading_pairs[:2]:  # Analyze first 2 pairs for speed
            market_data = self.get_market_data(pair.replace('-', ''))
            if market_data:
                change_24h = market_data['change_24h']
                
                # Simple trend analysis
                if change_24h > 5:
                    trend = "STRONG_BULLISH"
                    signal = "BUY"
                elif change_24h > 2:
                    trend = "BULLISH" 
                    signal = "HOLD"
                elif change_24h < -5:
                    trend = "STRONG_BEARISH"
                    signal = "SELL"
                elif change_24h < -2:
                    trend = "BEARISH"
                    signal = "HOLD"
                else:
                    trend = "NEUTRAL"
                    signal = "HOLD"
                
                trends[pair] = {
                    'price': market_data['price'],
                    'change_24h': change_24h,
                    'trend': trend,
                    'signal': signal,
                    'volume': market_data['volume'],
                    'timestamp': market_data['timestamp']
                }
        
        return trends
    
    def portfolio_health_check(self) -> Dict[str, Any]:
        """Analyze portfolio health and performance"""
        total_value = 0
        asset_count = len(self.portfolio['assets'])
        
        # Calculate current portfolio value
        for asset, details in self.portfolio['assets'].items():
            market_data = self.get_market_data(asset.replace('-', ''))
            if market_data:
                current_value = details['quantity'] * market_data['price']
                total_value += current_value
        
        # Update portfolio
        self.portfolio['total_value'] = total_value
        self._save_portfolio()
        
        return {
            'total_value': total_value,
            'asset_count': asset_count,
            'health_status': 'HEALTHY' if total_value > 0 else 'EMPTY',
            'last_updated': datetime.now().isoformat(),
            'recommendation': self._generate_portfolio_recommendation()
        }
    
    def _generate_portfolio_recommendation(self) -> str:
        """Generate portfolio recommendations based on market conditions"""
        trends = self.analyze_market_trends()
        
        bullish_count = sum(1 for data in trends.values() if data['trend'] in ['BULLISH', 'STRONG_BULLISH'])
        bearish_count = sum(1 for data in trends.values() if data['trend'] in ['BEARISH', 'STRONG_BEARISH'])
        
        if bullish_count > bearish_count:
            return "Consider increasing exposure to trending assets"
        elif bearish_count > bullish_count:
            return "Consider reducing exposure or setting stop losses"
        else:
            return "Market neutral - maintain current positions"
    
    def wealth_growth_strategy(self, initial_investment: float = 1000) -> Dict[str, Any]:
        """Generate wealth growth strategy with projections"""
        print("💰 Generating wealth growth strategy...")
        
        # Get market trends for strategy
        trends = self.analyze_market_trends()
        arbitrage_ops = self.scan_arbitrage_opportunities()
        
        # Simple projection model
        projected_growth = {
            'conservative': initial_investment * 1.15,  # 15% annual
            'moderate': initial_investment * 1.35,      # 35% annual  
            'aggressive': initial_investment * 1.75     # 75% annual
        }
        
        strategy = {
            'initial_investment': initial_investment,
            'projected_growth_1y': projected_growth,
            'recommended_assets': [],
            'arbitrage_opportunities': len(arbitrage_ops),
            'market_sentiment': self._calculate_market_sentiment(trends),
            'risk_assessment': 'MODERATE',
            'generated_at': datetime.now().isoformat()
        }
        
        # Recommend top assets based on trends
        for pair, data in list(trends.items())[:3]:
            if data['signal'] in ['BUY', 'HOLD']:
                strategy['recommended_assets'].append({
                    'asset': pair,
                    'signal': data['signal'],
                    'trend': data['trend']
                })
        
        # Store strategy in vault
        self.vault.store_conversation(
            "WEALTH_GROWTH_STRATEGY",
            f"Projected growth: ${projected_growth['moderate']:.2f} from ${initial_investment}",
            "trading"
        )
        
        return strategy
    
    def _calculate_market_sentiment(self, trends: Dict[str, Any]) -> str:
        """Calculate overall market sentiment"""
        sentiment_scores = {
            'STRONG_BULLISH': 2,
            'BULLISH': 1, 
            'NEUTRAL': 0,
            'BEARISH': -1,
            'STRONG_BEARISH': -2
        }
        
        total_score = sum(sentiment_scores[data['trend']] for data in trends.values())
        
        if total_score >= 3:
            return "VERY_BULLISH"
        elif total_score >= 1:
            return "BULLISH"
        elif total_score <= -3:
            return "VERY_BEARISH" 
        elif total_score <= -1:
            return "BEARISH"
        else:
            return "NEUTRAL"
    
    def automated_trading_signal(self) -> Dict[str, Any]:
        """Generate automated trading signals based on analysis"""
        trends = self.analyze_market_trends()
        arbitrage_ops = self.scan_arbitrage_opportunities()
        portfolio_health = self.portfolio_health_check()
        
        signals = []
        
        # Generate signals for each trading pair
        for pair, data in trends.items():
            if data['signal'] == 'BUY' and data['trend'] == 'STRONG_BULLISH':
                signals.append({
                    'action': 'BUY',
                    'pair': pair,
                    'confidence': 'HIGH',
                    'reason': f"Strong bullish trend: {data['change_24h']}% gain",
                    'price_target': data['price'] * 1.1  # 10% target
                })
            elif data['signal'] == 'SELL' and data['trend'] == 'STRONG_BEARISH':
                signals.append({
                    'action': 'SELL', 
                    'pair': pair,
                    'confidence': 'HIGH',
                    'reason': f"Strong bearish trend: {data['change_24h']}% loss",
                    'price_target': data['price'] * 0.9  # 10% downside
                })
        
        # Add arbitrage signals
        for opportunity in arbitrage_ops[:2]:  # Top 2 arbitrage opportunities
            signals.append({
                'action': 'ARBITRAGE',
                'pair': opportunity['pair'],
                'confidence': 'MEDIUM',
                'reason': f"Arbitrage opportunity: {opportunity['difference_percent']:.2f}% spread",
                'potential_profit': opportunity['potential_profit']
            })
        
        return {
            'signals': signals,
            'total_signals': len(signals),
            'market_sentiment': self._calculate_market_sentiment(trends),
            'portfolio_health': portfolio_health['health_status'],
            'generated_at': datetime.now().isoformat()
        }

    def execute_paper_trade(self, pair: str, action: str, amount_usd: float) -> Dict[str, Any]:
        """Simulate trade without real funds"""
        market_data = self.get_market_data(pair.replace('-', ''))
        price = market_data.get('price', 1.0)
        quantity = amount_usd / price if price > 0 else 0
        trade = {
            'trade_id': hashlib.md5(f"{pair}{action}{time.time()}".encode()).hexdigest()[:8],
            'pair': pair,
            'action': action.upper(),
            'amount_usd': amount_usd,
            'price': price,
            'quantity': quantity,
            'executed_at': datetime.now().isoformat(),
            'type': 'PAPER'
        }
        self.portfolio['trading_history'].append(trade)
        self._save_portfolio()
        return trade

    def set_stop_loss_trigger(self, pair: str, stop_loss_price: float, take_profit_price: float) -> Dict[str, Any]:
        """Set stop-loss and take-profit thresholds"""
        if 'triggers' not in self.portfolio:
            self.portfolio['triggers'] = {}
        self.portfolio['triggers'][pair] = {
            'stop_loss': stop_loss_price,
            'take_profit': take_profit_price,
            'set_at': datetime.now().isoformat()
        }
        self._save_portfolio()
        return {'pair': pair, 'stop_loss': stop_loss_price, 'take_profit': take_profit_price}

# Test the trading engine
if __name__ == "__main__":
    vault = CipherVault()
    trader = TradingEngine(vault)
    
    print("🧪 TESTING TRADING ENGINE...")
    
    # Test market data
    btc_data = trader.get_market_data('BTCUSDT')
    print(f"📊 BTC Price: ${btc_data.get('price', 'N/A')}")
    
    # Test arbitrage scanning
    arbitrage = trader.scan_arbitrage_opportunities()
    print(f"🔍 Arbitrage opportunities: {len(arbitrage)}")
    
    # Test market trends
    trends = trader.analyze_market_trends()
    print(f"📈 Market trends analyzed: {len(trends)} pairs")
    
    # Test trading signals
    signals = trader.automated_trading_signal()
    print(f"🎯 Trading signals: {signals['total_signals']}")