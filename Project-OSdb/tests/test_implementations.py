#!/usr/bin/env python3
"""
Integration Tests - Verify all implementations
"""

import sys
import os
import unittest
import tempfile
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.database import DatabaseManager
from core.encryption import EncryptionManager
from core.breach_checker import BreachChecker
from core.api_integrations import APIIntegrationManager
from core.data_import_export import DataImportExportManager

class TestCredentialsManager(unittest.TestCase):
    """Test Credentials Manager CRUD operations"""
    
    def setUp(self):
        self.db = DatabaseManager(':memory:')
        self.encryption = EncryptionManager()
        
        # Create test user
        user_id = self.create_test_user()
        self.user_id = user_id
    
    def create_test_user(self):
        """Create test user"""
        query = "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)"
        salt = self.encryption.generate_salt()
        password_hash = self.encryption.hash_password("testpass123", salt)
        self.db.execute_query(query, ("testuser", "test@example.com", password_hash, salt))
        
        # Get the user ID
        users = self.db.execute_query("SELECT id FROM users WHERE username = 'testuser'")
        return users[0]['id']
    
    def test_create_credential(self):
        """Test creating a credential"""
        encrypted_pass = self.encryption.encrypt_data("MySecurePass123!")
        
        query = """INSERT INTO credentials 
                  (user_id, service, username, password_encrypted, category, password_strength)
                  VALUES (?, ?, ?, ?, ?, ?)"""
        
        self.db.execute_query(query, (
            self.user_id,
            "Gmail",
            "user@gmail.com",
            encrypted_pass,
            "Email",
            4
        ))
        
        # Verify
        creds = self.db.execute_query("SELECT * FROM credentials WHERE user_id = ?", (self.user_id,))
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]['service'], "Gmail")
    
    def test_update_credential(self):
        """Test updating a credential"""
        # Create
        encrypted_pass = self.encryption.encrypt_data("OldPassword123")
        query = """INSERT INTO credentials 
                  (user_id, service, username, password_encrypted, category)
                  VALUES (?, ?, ?, ?, ?)"""
        self.db.execute_query(query, (self.user_id, "GitHub", "myuser", encrypted_pass, "Work"))
        
        # Update
        new_encrypted = self.encryption.encrypt_data("NewPassword456")
        update_query = "UPDATE credentials SET password_encrypted = ? WHERE service = ?"
        self.db.execute_query(update_query, (new_encrypted, "GitHub"))
        
        # Verify
        creds = self.db.execute_query("SELECT * FROM credentials WHERE service = ?", ("GitHub",))
        self.assertEqual(len(creds), 1)
        decrypted = self.encryption.decrypt_data(creds[0]['password_encrypted'])
        self.assertEqual(decrypted, "NewPassword456")
    
    def test_delete_credential(self):
        """Test deleting a credential"""
        # Create
        encrypted_pass = self.encryption.encrypt_data("TempPassword")
        query = """INSERT INTO credentials 
                  (user_id, service, username, password_encrypted, category)
                  VALUES (?, ?, ?, ?, ?)"""
        self.db.execute_query(query, (self.user_id, "Temporary", "tempuser", encrypted_pass, "General"))
        
        # Delete
        delete_query = "DELETE FROM credentials WHERE service = ?"
        self.db.execute_query(delete_query, ("Temporary",))
        
        # Verify
        creds = self.db.execute_query("SELECT * FROM credentials WHERE service = ?", ("Temporary",))
        self.assertEqual(len(creds), 0)

class TestBreachChecker(unittest.TestCase):
    """Test password breach checking"""
    
    def setUp(self):
        self.checker = BreachChecker()
    
    def test_breach_check_clean_password(self):
        """Test breach check returns clean for unknown password"""
        result = self.checker.check_password_breach("VeryUniquePassword12345!@#")
        self.assertIn('status', result)
        self.assertIn('found', result)
    
    def test_breach_check_error_handling(self):
        """Test breach checker handles errors gracefully"""
        result = self.checker.check_password_breach("")
        self.assertIn('status', result)
        self.assertIn('message', result)
    
    def test_cache_clearing(self):
        """Test cache clearing"""
        self.checker.cache['test'] = 'value'
        self.checker.clear_cache()
        self.assertEqual(len(self.checker.cache), 0)

class TestEncryption(unittest.TestCase):
    """Test encryption functionality"""
    
    def setUp(self):
        self.encryption = EncryptionManager()
    
    def test_aes_gcm_encryption(self):
        """Test AES-GCM encryption and decryption"""
        key = self.encryption.generate_salt(32)
        plaintext = "Secret message"
        
        encrypted = self.encryption.encrypt_data(plaintext, key, 'aes_gcm')
        decrypted = self.encryption.decrypt_data(encrypted, key, 'aes_gcm')
        
        self.assertEqual(decrypted, plaintext)
    
    def test_chacha20_encryption(self):
        """Test ChaCha20 encryption"""
        key = self.encryption.generate_salt(32)
        plaintext = "Another secret"
        
        encrypted = self.encryption.encrypt_data(plaintext, key, 'chacha20')
        decrypted = self.encryption.decrypt_data(encrypted, key, 'chacha20')
        
        self.assertEqual(decrypted, plaintext)
    
    def test_password_strength(self):
        """Test password strength verification"""
        weak = "password"
        strong = "MySecure!Pass123@2024"
        
        weak_analysis = self.encryption.verify_password_strength(weak)
        strong_analysis = self.encryption.verify_password_strength(strong)
        
        self.assertLess(weak_analysis['score'], strong_analysis['score'])
    
    def test_secure_password_generation(self):
        """Test secure password generation"""
        password = self.encryption.generate_secure_password(20)
        
        self.assertEqual(len(password), 20)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))

class TestDataImportExport(unittest.TestCase):
    """Test data import/export functionality"""
    
    def setUp(self):
        self.db = DatabaseManager(':memory:')
        self.encryption = EncryptionManager()
        self.manager = DataImportExportManager(self.db, self.encryption)
        
        # Create test user and data
        query = "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)"
        salt = self.encryption.generate_salt()
        password_hash = self.encryption.hash_password("test", salt)
        self.db.execute_query(query, ("testuser", "test@example.com", password_hash, salt))
        
        users = self.db.execute_query("SELECT id FROM users WHERE username = 'testuser'")
        self.user_id = users[0]['id']
    
    def test_export_to_json(self):
        """Test exporting data to JSON"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            success = self.manager.export_all_data(
                self.user_id,
                temp_file,
                format_type='json',
                include_credentials=True,
                include_notes=True,
                include_projects=True
            )
            
            self.assertTrue(success)
            self.assertTrue(os.path.exists(temp_file))
            
            # Verify content
            with open(temp_file, 'r') as f:
                data = json.load(f)
            
            self.assertIn('export_date', data)
            self.assertEqual(data['user_id'], self.user_id)
        
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)
    
    def test_csv_to_dict_list(self):
        """Test CSV to dict conversion"""
        csv_content = """Name,Age,City
John,30,NYC
Jane,25,LA"""
        
        result = self.manager._csv_to_dict_list(csv_content)
        
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['Name'], 'John')
        self.assertEqual(result[1]['City'], 'LA')

class TestAPIIntegrations(unittest.TestCase):
    """Test API integration framework"""
    
    def setUp(self):
        # This will skip real API calls without keys
        self.api = APIIntegrationManager()
    
    def test_api_result_dataclass(self):
        """Test APIResult dataclass"""
        from core.api_integrations import APIResult
        
        result = APIResult(
            source="TestAPI",
            data={"key": "value"},
            status="success",
            error=None
        )
        
        self.assertEqual(result.source, "TestAPI")
        self.assertEqual(result.status, "success")
        self.assertIsNone(result.error)
    
    def test_virustotal_no_key(self):
        """Test VirusTotal without API key"""
        result = self.api.virustotal_lookup("8.8.8.8", "ip")
        
        self.assertEqual(result.status, "skipped")
        self.assertIsNotNone(result.error)

class TestDatabaseSchema(unittest.TestCase):
    """Test database schema and constraints"""
    
    def setUp(self):
        self.db = DatabaseManager(':memory:')
    
    def test_users_table_exists(self):
        """Test users table exists"""
        query = "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        result = self.db.execute_query(query)
        self.assertGreater(len(result), 0)
    
    def test_credentials_table_exists(self):
        """Test credentials table exists"""
        query = "SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'"
        result = self.db.execute_query(query)
        self.assertGreater(len(result), 0)
    
    def test_project_tasks_table_exists(self):
        """Test project_tasks table exists"""
        query = "SELECT name FROM sqlite_master WHERE type='table' AND name='project_tasks'"
        result = self.db.execute_query(query)
        self.assertGreater(len(result), 0)
    
    def test_investigation_evidence_table_exists(self):
        """Test investigation_evidence table exists"""
        query = "SELECT name FROM sqlite_master WHERE type='table' AND name='investigation_evidence'"
        result = self.db.execute_query(query)
        self.assertGreater(len(result), 0)

def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseSchema))
    suite.addTests(loader.loadTestsFromTestCase(TestEncryption))
    suite.addTests(loader.loadTestsFromTestCase(TestCredentialsManager))
    suite.addTests(loader.loadTestsFromTestCase(TestBreachChecker))
    suite.addTests(loader.loadTestsFromTestCase(TestDataImportExport))
    suite.addTests(loader.loadTestsFromTestCase(TestAPIIntegrations))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
