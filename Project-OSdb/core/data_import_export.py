"""
Data Import/Export Manager - Handle data migration and backup
"""

import json
import csv
import sqlite3
import logging
from datetime import datetime
from typing import Dict, List, Optional
import zipfile
import os

logger = logging.getLogger(__name__)

class DataImportExportManager:
    """Manage data import and export operations"""
    
    def __init__(self, db_manager, encryption_manager):
        self.db = db_manager
        self.encryption = encryption_manager
    
    def export_all_data(self, user_id: int, export_path: str, format_type: str = 'json',
                       include_credentials: bool = True, 
                       include_notes: bool = True,
                       include_projects: bool = True,
                       encrypt: bool = False) -> bool:
        """Export all user data"""
        try:
            data = {
                'export_date': datetime.now().isoformat(),
                'format_version': '1.0',
                'user_id': user_id
            }
            
            # Export credentials
            if include_credentials:
                query = "SELECT * FROM credentials WHERE user_id = ?"
                credentials = self.db.execute_query(query, (user_id,))
                data['credentials'] = [dict(c) for c in credentials]
            
            # Export notes
            if include_notes:
                query = "SELECT * FROM secure_notes WHERE user_id = ?"
                notes = self.db.execute_query(query, (user_id,))
                data['notes'] = [dict(n) for n in notes]
            
            # Export projects
            if include_projects:
                query = "SELECT * FROM osint_projects WHERE user_id = ?"
                projects = self.db.execute_query(query, (user_id,))
                data['projects'] = [dict(p) for p in projects]
                
                # Export project tasks and evidence
                data['tasks'] = []
                data['evidence'] = []
                
                for project in projects:
                    # Tasks
                    task_query = "SELECT * FROM project_tasks WHERE project_id = ?"
                    tasks = self.db.execute_query(task_query, (project['id'],))
                    data['tasks'].extend([dict(t) for t in tasks])
                    
                    # Evidence
                    ev_query = "SELECT * FROM investigation_evidence WHERE project_id = ?"
                    evidence = self.db.execute_query(ev_query, (project['id'],))
                    data['evidence'].extend([dict(e) for e in evidence])
            
            # Export to format
            if format_type == 'json':
                export_data = json.dumps(data, indent=2, default=str)
                
                if encrypt:
                    # Encrypt the export
                    export_data = self.encryption.encrypt_data(export_data)
                
                with open(export_path, 'w') as f:
                    f.write(export_data)
            
            elif format_type == 'csv':
                with zipfile.ZipFile(export_path, 'w') as zf:
                    # Export credentials to CSV
                    if 'credentials' in data:
                        csv_content = self._dict_list_to_csv(data['credentials'])
                        zf.writestr('credentials.csv', csv_content)
                    
                    # Export notes to CSV
                    if 'notes' in data:
                        csv_content = self._dict_list_to_csv(data['notes'])
                        zf.writestr('notes.csv', csv_content)
                    
                    # Export projects to CSV
                    if 'projects' in data:
                        csv_content = self._dict_list_to_csv(data['projects'])
                        zf.writestr('projects.csv', csv_content)
                    
                    # Export tasks to CSV
                    if 'tasks' in data:
                        csv_content = self._dict_list_to_csv(data['tasks'])
                        zf.writestr('tasks.csv', csv_content)
                    
                    # Export evidence to CSV
                    if 'evidence' in data:
                        csv_content = self._dict_list_to_csv(data['evidence'])
                        zf.writestr('evidence.csv', csv_content)
            
            elif format_type == 'zip':
                with zipfile.ZipFile(export_path, 'w') as zf:
                    json_data = json.dumps(data, indent=2, default=str)
                    if encrypt:
                        json_data = self.encryption.encrypt_data(json_data)
                    zf.writestr('data.json', json_data)
            
            logger.info(f"Data export completed: {export_path}")
            return True
        
        except Exception as e:
            logger.error(f"Data export failed: {e}")
            return False
    
    def import_data(self, user_id: int, import_path: str, 
                   encrypted: bool = False, password: str = None) -> Dict[str, any]:
        """Import data from export file"""
        try:
            # Detect format
            if import_path.endswith('.json'):
                with open(import_path, 'r') as f:
                    content = f.read()
                
                if encrypted and password:
                    content = self.encryption.decrypt_data(content)
                
                data = json.loads(content)
            
            elif import_path.endswith('.zip'):
                with zipfile.ZipFile(import_path, 'r') as zf:
                    if 'data.json' in zf.namelist():
                        content = zf.read('data.json').decode()
                        if encrypted and password:
                            content = self.encryption.decrypt_data(content)
                        data = json.loads(content)
                    else:
                        # Import from CSV files
                        data = self._import_from_zip(zf, user_id)
            
            else:
                return {'success': False, 'error': 'Unsupported file format'}
            
            # Import data
            results = {
                'credentials': 0,
                'notes': 0,
                'projects': 0,
                'tasks': 0,
                'evidence': 0,
                'errors': []
            }
            
            # Import credentials
            if 'credentials' in data:
                for cred in data['credentials']:
                    try:
                        query = """INSERT INTO credentials 
                                 (user_id, service, username, password_encrypted, url, category, 
                                  tags, notes, password_strength, expires_at)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
                        
                        self.db.execute_query(query, (
                            user_id,
                            cred.get('service'),
                            cred.get('username'),
                            cred.get('password_encrypted'),
                            cred.get('url'),
                            cred.get('category', 'General'),
                            cred.get('tags', '[]'),
                            cred.get('notes'),
                            cred.get('password_strength', 1),
                            cred.get('expires_at')
                        ))
                        results['credentials'] += 1
                    except Exception as e:
                        results['errors'].append(f"Credential import failed: {e}")
            
            # Import notes
            if 'notes' in data:
                for note in data['notes']:
                    try:
                        query = """INSERT INTO secure_notes 
                                 (user_id, title, content_encrypted, category, tags)
                                 VALUES (?, ?, ?, ?, ?)"""
                        
                        self.db.execute_query(query, (
                            user_id,
                            note.get('title'),
                            note.get('content_encrypted'),
                            note.get('category', 'General'),
                            note.get('tags', '[]')
                        ))
                        results['notes'] += 1
                    except Exception as e:
                        results['errors'].append(f"Note import failed: {e}")
            
            # Import projects (needs project mapping)
            project_map = {}
            if 'projects' in data:
                for project in data['projects']:
                    try:
                        query = """INSERT INTO osint_projects 
                                 (user_id, name, description, status, priority, tags, budget)
                                 VALUES (?, ?, ?, ?, ?, ?, ?)"""
                        
                        self.db.execute_query(query, (
                            user_id,
                            project.get('name'),
                            project.get('description'),
                            project.get('status', 'active'),
                            project.get('priority', 1),
                            project.get('tags', '[]'),
                            project.get('budget', 0)
                        ))
                        
                        # Get the new project ID
                        new_projects = self.db.execute_query(
                            "SELECT id FROM osint_projects WHERE user_id = ? AND name = ? ORDER BY id DESC LIMIT 1",
                            (user_id, project.get('name'))
                        )
                        if new_projects:
                            project_map[project['id']] = new_projects[0]['id']
                        
                        results['projects'] += 1
                    except Exception as e:
                        results['errors'].append(f"Project import failed: {e}")
            
            # Import tasks
            if 'tasks' in data:
                for task in data['tasks']:
                    try:
                        new_project_id = project_map.get(task.get('project_id'))
                        if not new_project_id:
                            continue
                        
                        query = """INSERT INTO project_tasks 
                                 (project_id, user_id, title, description, status, priority, 
                                  assigned_to, due_date)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""
                        
                        self.db.execute_query(query, (
                            new_project_id,
                            user_id,
                            task.get('title'),
                            task.get('description'),
                            task.get('status', 'pending'),
                            task.get('priority', 1),
                            task.get('assigned_to'),
                            task.get('due_date')
                        ))
                        results['tasks'] += 1
                    except Exception as e:
                        results['errors'].append(f"Task import failed: {e}")
            
            # Import evidence
            if 'evidence' in data:
                for ev in data['evidence']:
                    try:
                        new_project_id = project_map.get(ev.get('project_id'))
                        if not new_project_id:
                            continue
                        
                        query = """INSERT INTO investigation_evidence 
                                 (project_id, user_id, evidence_type, description, 
                                  credibility_score, verified)
                                 VALUES (?, ?, ?, ?, ?, ?)"""
                        
                        self.db.execute_query(query, (
                            new_project_id,
                            user_id,
                            ev.get('evidence_type'),
                            ev.get('description'),
                            ev.get('credibility_score', 3),
                            ev.get('verified', 0)
                        ))
                        results['evidence'] += 1
                    except Exception as e:
                        results['errors'].append(f"Evidence import failed: {e}")
            
            results['success'] = len(results['errors']) == 0
            logger.info(f"Data import completed: {results}")
            return results
        
        except Exception as e:
            logger.error(f"Data import failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _dict_list_to_csv(self, data: List[Dict]) -> str:
        """Convert list of dicts to CSV string"""
        if not data:
            return ""
        
        keys = data[0].keys()
        output = []
        
        # Header
        output.append(','.join(str(k) for k in keys))
        
        # Rows
        for row in data:
            values = []
            for k in keys:
                val = row.get(k, '')
                # Escape CSV
                if isinstance(val, str) and (',' in val or '"' in val or '\n' in val):
                    val = f'"{val.replace(chr(34), chr(34) + chr(34))}"'
                values.append(str(val))
            output.append(','.join(values))
        
        return '\n'.join(output)
    
    def _import_from_zip(self, zf: zipfile.ZipFile, user_id: int) -> Dict:
        """Import from CSV files in ZIP"""
        data = {}
        
        # Import credentials
        if 'credentials.csv' in zf.namelist():
            data['credentials'] = self._csv_to_dict_list(zf.read('credentials.csv').decode())
        
        # Import notes
        if 'notes.csv' in zf.namelist():
            data['notes'] = self._csv_to_dict_list(zf.read('notes.csv').decode())
        
        # Import projects
        if 'projects.csv' in zf.namelist():
            data['projects'] = self._csv_to_dict_list(zf.read('projects.csv').decode())
        
        # Import tasks
        if 'tasks.csv' in zf.namelist():
            data['tasks'] = self._csv_to_dict_list(zf.read('tasks.csv').decode())
        
        # Import evidence
        if 'evidence.csv' in zf.namelist():
            data['evidence'] = self._csv_to_dict_list(zf.read('evidence.csv').decode())
        
        return data
    
    def _csv_to_dict_list(self, csv_content: str) -> List[Dict]:
        """Convert CSV content to list of dicts"""
        reader = csv.DictReader(csv_content.strip().split('\n'))
        return list(reader)
