#!/usr/bin/env python3
import os
import json
from run_forensics import SimpleForensicAnalyzer

def main():
    # Initialize the forensic analyzer
    analyzer = SimpleForensicAnalyzer()
    
    # Get list of contracts from the reports folder
    reports_dir = "reports"
    contracts = []
    
    for file in os.listdir(reports_dir):
        if file.endswith("_report.json"):
            contract_name = file.replace("_report.json", "")
            contracts.append(contract_name)
    
    if not contracts:
        print("[X] No contracts found in reports directory")
        return
    
    print(f"[*] Found {len(contracts)} contracts to analyze")
    
    # Run forensic analysis for each contract
    for contract in contracts:
        print(f"\n[===] Running forensic analysis for {contract} [===]")
        
        # Generate a simulated contract address
        contract_address = analyzer._generate_address(seed=contract)
        
        # Run all forensic analysis steps
        try:
            # 1. Analyze contract history
            history_file = analyzer.analyze_contract_history(contract_address)
            
            # 2. Identify suspicious actors
            actors_file = analyzer.identify_suspicious_actors(contract_address)
            
            # 3. Reconstruct potential attacks
            vulnerability_report = os.path.join(reports_dir, f"{contract}_report.json")
            attack_file = analyzer.reconstruct_attack(contract_address, vulnerability_report)
            
            # 4. Generate comprehensive report
            report_file = analyzer.generate_forensic_report(contract_address, vulnerability_report)
            
            print(f"[✓] Forensic analysis completed for {contract}")
            
        except Exception as e:
            print(f"[X] Error analyzing {contract}: {str(e)}")
            continue
    
    print("\n[✓] Forensic analysis completed for all contracts")
    print(f"[*] Results are saved in the 'forensics' directory")

if __name__ == "__main__":
    main() 