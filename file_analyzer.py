#!/usr/bin/env python3
# file_analyzer.py - Read and analyze local files/code

import os
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional

class FileAnalyzer:
    """
    Analyze local files, code, and project structures
    """
    
    def __init__(self, vault):
        self.vault = vault
        self.supported_extensions = {
            'code': ['.py', '.js', '.java', '.cpp', '.c', '.html', '.css', '.php', '.rb', '.go'],
            'data': ['.json', '.xml', '.yaml', '.yml', '.csv', '.txt'],
            'docs': ['.md', '.rst', '.txt', '.docx', '.pdf'],
            'config': ['.conf', '.cfg', '.ini', '.toml']
        }
    
    def scan_project(self, base_path: str = ".") -> Dict[str, Any]:
        """Scan a project directory and analyze its structure"""
        base_path = os.path.expanduser(base_path)
        if not os.path.exists(base_path):
            return {"error": f"Path does not exist: {base_path}"}
        
        print(f"🔍 Scanning project: {base_path}")
        project_info = {
            'path': base_path,
            'scan_time': self._current_timestamp(),
            'files_by_type': {},
            'total_size': 0,
            'file_count': 0,
            'recent_files': []
        }
        
        # Scan directory
        for root, dirs, files in os.walk(base_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_info = self._analyze_file(file_path)
                
                if file_info:
                    # Categorize by extension
                    ext = file_info['extension']
                    category = self._categorize_extension(ext)
                    
                    if category not in project_info['files_by_type']:
                        project_info['files_by_type'][category] = []
                    
                    project_info['files_by_type'][category].append(file_info)
                    project_info['total_size'] += file_info['size']
                    project_info['file_count'] += 1
        
        # Get recent files (last 10 modified)
        recent_files = self._get_recent_files(base_path, limit=10)
        project_info['recent_files'] = recent_files
        
        # Store project info in vault
        self.vault.store_conversation(
            f"PROJECT_SCAN: {os.path.basename(base_path)}",
            f"Files: {project_info['file_count']} | Size: {project_info['total_size']} bytes | Types: {list(project_info['files_by_type'].keys())}",
            context_tag="project_scan"
        )
        
        return project_info
    
    def _analyze_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Analyze a single file"""
        try:
            stat = os.stat(file_path)
            file_size = stat.st_size
            
            # Skip very large files
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                return None
            
            extension = os.path.splitext(file_path)[1].lower()
            
            file_info = {
                'path': file_path,
                'name': os.path.basename(file_path),
                'size': file_size,
                'extension': extension,
                'modified': stat.st_mtime,
                'content_preview': '',
                'line_count': 0
            }
            
            # Read content for supported file types
            if extension in self.supported_extensions['code'] + self.supported_extensions['data'] + self.supported_extensions['docs']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        file_info['line_count'] = len(content.splitlines())
                        
                        # Create preview (first 200 chars)
                        preview = content[:200].replace('\n', ' ')
                        file_info['content_preview'] = preview
                        
                        # For code files, detect language features
                        if extension == '.py':
                            file_info['language'] = 'python'
                            file_info['features'] = self._analyze_python_features(content)
                        
                except Exception as e:
                    file_info['read_error'] = str(e)
            
            return file_info
            
        except Exception as e:
            return None
    
    def _analyze_python_features(self, content: str) -> List[str]:
        """Detect Python-specific features in code"""
        features = []
        
        if 'import ' in content:
            features.append('imports')
        if 'def ' in content:
            features.append('functions')
        if 'class ' in content:
            features.append('classes')
        if 'requests.' in content or 'http.client' in content:
            features.append('http_requests')
        if 'cryptography' in content or 'Fernet' in content:
            features.append('encryption')
        if 'socket.' in content:
            features.append('networking')
        if 'subprocess.' in content or 'os.system' in content:
            features.append('system_calls')
        
        return features
    
    def _categorize_extension(self, extension: str) -> str:
        """Categorize file by extension"""
        for category, exts in self.supported_extensions.items():
            if extension in exts:
                return category
        return 'other'
    
    def _get_recent_files(self, base_path: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most recently modified files"""
        recent_files = []
        
        for root, dirs, files in os.walk(base_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    mtime = os.path.getmtime(file_path)
                    recent_files.append({
                        'path': file_path,
                        'name': file,
                        'modified': mtime,
                        'size': os.path.getsize(file_path)
                    })
                except Exception:
                    continue
        
        # Sort by modification time (newest first)
        recent_files.sort(key=lambda x: x['modified'], reverse=True)
        return recent_files[:limit]
    
    def read_file_content(self, file_path: str, max_lines: int = 50) -> Dict[str, Any]:
        """Read file content with line limit"""
        file_path = os.path.expanduser(file_path)
        
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        
        if os.path.getsize(file_path) > 5 * 1024 * 1024:  # 5MB limit
            return {"error": "File too large to read"}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            content = {
                'path': file_path,
                'total_lines': len(lines),
                'content': ''.join(lines[:max_lines]),
                'truncated': len(lines) > max_lines
            }
            
            return content
            
        except Exception as e:
            return {"error": f"Read error: {str(e)}"}
    
    def search_in_files(self, search_term: str, base_path: str = ".", file_extensions: List[str] = None) -> Dict[str, Any]:
        """Search for text in files"""
        base_path = os.path.expanduser(base_path)
        results = []
        
        if not file_extensions:
            file_extensions = self.supported_extensions['code'] + self.supported_extensions['docs']
        
        for root, dirs, files in os.walk(base_path):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in file_extensions:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if search_term.lower() in content.lower():
                                # Count occurrences
                                count = content.lower().count(search_term.lower())
                                results.append({
                                    'file': file_path,
                                    'occurrences': count,
                                    'preview': self._extract_context(content, search_term)
                                })
                    except Exception:
                        continue
        
        return {
            'search_term': search_term,
            'base_path': base_path,
            'results_found': len(results),
            'results': sorted(results, key=lambda x: x['occurrences'], reverse=True)[:10]  # Top 10
        }
    
    def _extract_context(self, content: str, search_term: str, context_chars: int = 100) -> str:
        """Extract context around search term"""
        import re
        pattern = re.compile(re.escape(search_term), re.IGNORECASE)
        match = pattern.search(content)
        
        if match:
            start = max(0, match.start() - context_chars)
            end = min(len(content), match.end() + context_chars)
            return content[start:end].replace('\n', ' ')
        
        return ""
    
    def _current_timestamp(self) -> str:
        """Get current timestamp string"""
        from datetime import datetime
        return datetime.now().isoformat()


if __name__ == "__main__":
    from cipher_vault import CipherVault
    vault = CipherVault()
    analyzer = FileAnalyzer(vault)
    
    print("🧪 Testing File Analyzer:")
    project_scan = analyzer.scan_project(".")
    print(f"Project scan: {project_scan['file_count']} files found")
    
    # Test file reading
    if project_scan['file_count'] > 0:
        test_file = project_scan['files_by_type']['code'][0]['path'] if 'code' in project_scan['files_by_type'] else None
        if test_file:
            content = analyzer.read_file_content(test_file, max_lines=5)
            print(f"File preview: {content.get('content', '')[:100]}...")