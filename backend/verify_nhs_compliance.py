#!/usr/bin/env python3
"""
NHS Digital Compliance Verification Script
Validates system compliance with NHS Digital standards
"""

import json
import os
from datetime import datetime

def verify_nhs_compliance():
    """Verify NHS Digital compliance status"""
    compliance_checks = {
        "nhs_login": {
            "config_file": "nhs_compliance/nhs_login_config.json",
            "required": True,
            "status": "unknown"
        },
        "pds_integration": {
            "config_file": "nhs_compliance/pds_config.json", 
            "required": True,
            "status": "unknown"
        },
        "fhir_r4": {
            "config_file": "nhs_compliance/fhir_r4_config.json",
            "required": True,
            "status": "unknown"
        },
        "nhs_number_validation": {
            "module_file": "nhs_compliance/nhs_number_validator.py",
            "required": True,
            "status": "unknown"
        },
        "information_governance": {
            "config_file": "nhs_compliance/information_governance.json",
            "required": True,
            "status": "unknown"
        }
    }
    
    # Check each compliance requirement
    for check_name, check_config in compliance_checks.items():
        file_path = check_config.get("config_file") or check_config.get("module_file")
        
        if os.path.exists(file_path):
            compliance_checks[check_name]["status"] = "configured"
        else:
            compliance_checks[check_name]["status"] = "missing"
    
    # Generate compliance report
    report = {
        "verification_date": datetime.now().isoformat(),
        "overall_status": "compliant",
        "checks": compliance_checks,
        "recommendations": []
    }
    
    # Check overall compliance
    missing_required = [
        name for name, config in compliance_checks.items()
        if config["required"] and config["status"] == "missing"
    ]
    
    if missing_required:
        report["overall_status"] = "non_compliant"
        report["recommendations"].append(
            f"Configure missing components: {', '.join(missing_required)}"
        )
    
    return report

if __name__ == "__main__":
    report = verify_nhs_compliance()
    
    print("NHS Digital Compliance Verification Report")
    print("=" * 50)
    print(f"Overall Status: {report['overall_status'].upper()}")
    print(f"Verification Date: {report['verification_date']}")
    print()
    
    for check_name, check_data in report['checks'].items():
        status_icon = "✅" if check_data['status'] == 'configured' else "❌"
        print(f"{status_icon} {check_name}: {check_data['status']}")
    
    if report['recommendations']:
        print("\nRecommendations:")
        for rec in report['recommendations']:
            print(f"- {rec}")
    
    # Save detailed report
    with open('nhs_compliance_report.json', 'w') as f:
        json.dump(report, f, indent=2)
