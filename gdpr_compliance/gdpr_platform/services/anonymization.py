import hashlib
import uuid
import re
from datetime import datetime, timedelta
import random
from typing import Any, Dict, List
import logging
from .encryption import encryption_service

logger = logging.getLogger(__name__)

class AnonymizationService:
    """
    Service for handling data anonymization and pseudonymization
    """
    
    def __init__(self):
        self.salt = uuid.uuid4().hex
        self._setup_patterns()
    
    def _setup_patterns(self):
        """Setup regex patterns for identifying sensitive data"""
        self.patterns = {
            'email': r'[^@]+@[^@]+\.[^@]+',
            'phone': r'\+?[\d\-\(\)\s]{10,}',
            'ip': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        }
    
    def pseudonymize_data(self, data: Dict[str, Any], fields_to_pseudo: List[str]) -> Dict[str, Any]:
        """
        Pseudonymize specific fields while maintaining referential integrity
        """
        try:
            result = data.copy()
            mapping = {}
            
            for field in fields_to_pseudo:
                if field in result:
                    original_value = str(result[field])
                    if original_value in mapping:
                        # Use existing pseudonym for referential integrity
                        result[field] = mapping[original_value]
                    else:
                        # Generate new pseudonym
                        pseudo_value = self._generate_pseudonym(original_value)
                        mapping[original_value] = pseudo_value
                        result[field] = pseudo_value
            
            # Store mapping for potential re-identification
            self._store_mapping(mapping)
            return result
            
        except Exception as e:
            logger.error(f"Pseudonymization error: {str(e)}")
            raise ValueError("Failed to pseudonymize data")
    
    def anonymize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fully anonymize data by removing or obfuscating identifying information
        """
        try:
            result = data.copy()
            
            for key, value in result.items():
                if isinstance(value, str):
                    # Check for patterns and anonymize accordingly
                    for pattern_type, pattern in self.patterns.items():
                        if re.match(pattern, value):
                            result[key] = self._anonymize_by_type(value, pattern_type)
                elif isinstance(value, (int, float)):
                    # Generalize numerical values
                    result[key] = self._generalize_number(value)
                elif isinstance(value, datetime):
                    # Generalize dates to month/year
                    result[key] = value.replace(day=1)
            
            return result
            
        except Exception as e:
            logger.error(f"Anonymization error: {str(e)}")
            raise ValueError("Failed to anonymize data")
    
    def _generate_pseudonym(self, value: str) -> str:
        """Generate consistent pseudonym for a value"""
        hash_input = f"{value}{self.salt}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:12]
    
    def _store_mapping(self, mapping: Dict[str, str]):
        """Store pseudonymization mapping securely"""
        encrypted_mapping = encryption_service.encrypt_data(mapping)
        # Store in secure location (e.g., separate database table)
        # Implementation depends on storage requirements
    
    def _anonymize_by_type(self, value: str, pattern_type: str) -> str:
        """Anonymize value based on its type"""
        if pattern_type == 'email':
            return f"anonymous_{uuid.uuid4().hex[:8]}@example.com"
        elif pattern_type == 'phone':
            return "+XXX-XXX-XXXX"
        elif pattern_type == 'ip':
            return "XXX.XXX.XXX.XXX"
        elif pattern_type == 'credit_card':
            return "XXXX-XXXX-XXXX-XXXX"
        elif pattern_type == 'ssn':
            return "XXX-XX-XXXX"
        return "REDACTED"
    
    def _generalize_number(self, value: float) -> float:
        """Generalize numerical values to ranges"""
        if value < 10:
            return round(value * 0.8, 1)
        elif value < 100:
            return round(value, -1)
        else:
            return round(value, -2)
    
    def k_anonymize(self, dataset: List[Dict[str, Any]], k: int = 5) -> List[Dict[str, Any]]:
        """
        Implement k-anonymity by generalizing data until each record appears k times
        """
        try:
            if len(dataset) < k:
                return [self.anonymize_data(record) for record in dataset]
            
            result = []
            groups = {}
            
            # Group similar records
            for record in dataset:
                key = self._get_generalization_key(record)
                if key not in groups:
                    groups[key] = []
                groups[key].append(record)
            
            # Process each group
            for group in groups.values():
                if len(group) < k:
                    # Anonymize small groups
                    result.extend([self.anonymize_data(record) for record in group])
                else:
                    # Keep groups that meet k-anonymity
                    result.extend(group)
            
            return result
            
        except Exception as e:
            logger.error(f"K-anonymization error: {str(e)}")
            raise ValueError("Failed to k-anonymize dataset")
    
    def _get_generalization_key(self, record: Dict[str, Any]) -> str:
        """Generate key for grouping similar records"""
        key_parts = []
        for key, value in sorted(record.items()):
            if isinstance(value, (int, float)):
                # Generalize numbers to ranges
                key_parts.append(f"{key}:{self._generalize_number(value)}")
            elif isinstance(value, datetime):
                # Generalize dates to month
                key_parts.append(f"{key}:{value.year}-{value.month}")
            elif isinstance(value, str):
                # Use first few characters for strings
                key_parts.append(f"{key}:{value[:3]}")
        return "|".join(key_parts)

# Global anonymization service instance
anonymization_service = AnonymizationService() 