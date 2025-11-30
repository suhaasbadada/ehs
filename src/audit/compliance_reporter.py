# src/audit/compliance_reporter.py
"""Compliance reporting utilities"""

class ComplianceReporter:
    """Generates compliance reports"""
    
    @staticmethod
    def generate_hipaa_report(audit_logs, start_date, end_date):
        """Generate HIPAA compliance report"""
        return {
            'standard': 'HIPAA',
            'period': {'start': start_date, 'end': end_date},
            'logs': audit_logs
        }
    
    @staticmethod
    def generate_gdpr_report(audit_logs, start_date, end_date):
        """Generate GDPR compliance report"""
        return {
            'standard': 'GDPR',
            'period': {'start': start_date, 'end': end_date},
            'logs': audit_logs
        }
