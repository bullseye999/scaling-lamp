#!/usr/bin/env python3
# memory_engine.py - Advanced memory with semantic search

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from cipher_vault import CipherVault

class MemoryEngine:
    """
    Enhanced memory system with semantic search and knowledge graphs.
    Works with the existing CipherVault.
    """
    
    def __init__(self, vault: CipherVault):
        self.vault = vault
        self.knowledge_graph = {}
        self._load_knowledge_graph()
        
    def _load_knowledge_graph(self):
        """Load knowledge graph from vault config"""
        kg_data = self.vault.get_config("knowledge_graph")
        if kg_data:
            try:
                self.knowledge_graph = json.loads(kg_data)
                # Convert sets back from lists (JSON can't store sets)
                for entity, data in self.knowledge_graph.items():
                    data['tags'] = set(data.get('tags', []))
                    data['related_entities'] = set(data.get('related_entities', []))
            except Exception:
                self.knowledge_graph = {}
    
    def _save_knowledge_graph(self):
        """Save knowledge graph to vault config"""
        # Convert sets to lists for JSON serialization
        kg_serializable = {}
        for entity, data in self.knowledge_graph.items():
            kg_serializable[entity] = {
                'tags': list(data.get('tags', [])),
                'related_entities': list(data.get('related_entities', [])),
                'last_mentioned': data.get('last_mentioned', '')
            }
        self.vault.set_config("knowledge_graph", json.dumps(kg_serializable))
    
    def auto_tag_conversation(self, prompt: str, response: str) -> List[str]:
        """Automatically generate tags based on content"""
        tags = []
        content = f"{prompt} {response}".lower()
        
        # Simple keyword-based tagging (will be AI-enhanced later)
        tag_keywords = {
            'threat_intel': ['hack', 'security', 'breach', 'malware', 'attack', 'vulnerability', 'exploit'],
            'tech': ['python', 'code', 'server', 'linux', 'api', 'programming', 'development'],
            'strategy': ['plan', 'strategy', 'decision', 'analysis', 'scenario', 'tactical'],
            'personal': ['remember', 'important', 'note to self', 'my project', 'i need'],
            'opsec': ['encrypt', 'secure', 'privacy', 'vpn', 'tor', 'anonymous'],
            'ai': ['neural', 'model', 'llm', 'gpt', 'claude', 'machine learning']
        }
        
        for tag, keywords in tag_keywords.items():
            if any(keyword in content for keyword in keywords):
                tags.append(tag)
                
        return tags if tags else ['general']
    
    def store_intelligent_memory(self, prompt: str, response: str) -> List[str]:
        """Store conversation with auto-tagging and knowledge extraction"""
        # Auto-generate tags
        tags = self.auto_tag_conversation(prompt, response)
        primary_tag = tags[0] if tags else 'general'
        
        # Store in vault with intelligent tagging
        self.vault.store_conversation(prompt, response, context_tag=primary_tag)
        
        # Update knowledge graph
        self._update_knowledge_graph(prompt, response, tags)
        
        return tags
    
    def _update_knowledge_graph(self, prompt: str, response: str, tags: List[str]):
        """Build a simple knowledge graph of related concepts"""
        # Extract entities (simple version - will be AI-enhanced)
        entities = self._extract_entities(f"{prompt} {response}")
        
        for entity in entities:
            if entity not in self.knowledge_graph:
                self.knowledge_graph[entity] = {
                    'tags': set(tags),
                    'related_entities': set(),
                    'last_mentioned': datetime.now().isoformat()
                }
            else:
                self.knowledge_graph[entity]['tags'].update(tags)
                self.knowledge_graph[entity]['last_mentioned'] = datetime.now().isoformat()
        
        # Save updated knowledge graph
        self._save_knowledge_graph()
    
    def _extract_entities(self, text: str) -> List[str]:
        """Simple entity extraction (placeholder for AI enhancement)"""
        # For now, return words that look like important concepts
        words = text.split()
        entities = []
        for word in words:
            clean_word = word.strip('.,!?":;()[]{}').lower()
            # Consider multi-word entities and important terms
            if len(clean_word) > 4 and clean_word not in ['which', 'about', 'would', 'could', 'should']:
                entities.append(clean_word.title())
        
        return list(set(entities))  # Remove duplicates
    
    def semantic_search(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Basic semantic search through conversation history"""
        all_conversations = self.vault.get_recent_conversations(limit=100)
        results = []
        
        for conv in all_conversations:
            content = f"{conv['prompt']} {conv['response']}".lower()
            query_lower = query.lower()
            
            # Simple scoring based on keyword matches
            score = sum(1 for word in query_lower.split() if word in content)
            
            if score > 0:
                results.append({
                    'conversation': conv,
                    'score': score,
                    'matched_query': query
                })
        
        # Sort by score and return top results
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:limit]
    
    def get_related_concepts(self, concept: str) -> List[str]:
        """Get concepts related to the given one"""
        concept_key = concept.title()
        if concept_key in self.knowledge_graph:
            return list(self.knowledge_graph[concept_key]['related_entities'])
        return []
    
    def get_conversations_by_tag(self, tag: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get conversations by specific tag"""
        return self.vault.get_recent_conversations(limit=limit, context_tag=tag)
    
    def get_knowledge_graph_stats(self) -> Dict[str, Any]:
        """Return statistics about the knowledge graph"""
        return {
            'total_entities': len(self.knowledge_graph),
            'entities_by_tag': {tag: sum(1 for data in self.knowledge_graph.values() if tag in data['tags']) 
                              for tag in ['threat_intel', 'tech', 'strategy', 'personal', 'opsec', 'ai']},
            'most_recent_entities': sorted([(entity, data['last_mentioned']) 
                                         for entity, data in self.knowledge_graph.items()], 
                                        key=lambda x: x[1], reverse=True)[:5]
        }

# Test the memory engine
if __name__ == "__main__":
    vault = CipherVault()
    memory = MemoryEngine(vault)
    
    # Test intelligent storage
    tags = memory.store_intelligent_memory(
        "What's the latest Python security vulnerability?",
        "There's a new exploit in Python 3.12.3 that affects cryptographic libraries. We should update immediately."
    )
    print(f"Auto-generated tags: {tags}")
    
    # Test semantic search
    results = memory.semantic_search("Python security")
    print(f"Search results: {len(results)} found")
    for result in results:
        print(f"Score {result['score']}: {result['conversation']['prompt']}")
    
    # Test knowledge graph
    kg_stats = memory.get_knowledge_graph_stats()
    print(f"Knowledge graph stats: {kg_stats}")
