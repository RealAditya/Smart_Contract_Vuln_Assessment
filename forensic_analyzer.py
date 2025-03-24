#!/usr/bin/env python3
import os
import json
import argparse
from forensics import ForensicAnalyzer

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Blockchain Forensic Analysis Tool')
    parser.add_argument('--contract', '-c', type=str, required=True,
                        help='Contract address to analyze')
    parser.add_argument('--report', '-r', type=str, default='consolidated_security_report.json',
                        help='Path to vulnerability report (default: consolidated_security_report.json)')
    parser.add_argument('--provider', '-p', type=str,
                        help='Ethereum provider URL (default: uses Infura)')
    parser.add_argument('--depth', '-d', type=int, default=2,
                        help='Depth for funds flow analysis (default: 2)')
    parser.add_argument('--history-only', action='store_true',
                        help='Only perform contract history analysis')
    parser.add_argument('--suspicious-only', action='store_true',
                        help='Only perform suspicious actor analysis')
    parser.add_argument('--flow-only', action='store_true',
                        help='Only perform funds flow analysis')
    parser.add_argument('--attack-only', action='store_true',
                        help='Only perform attack reconstruction')
    
    args = parser.parse_args()
    
    print("[===] Blockchain Forensic Analysis Tool [===]")
    print(f"[*] Target Contract: {args.contract}")
    
    # Initialize analyzer
    try:
        analyzer = ForensicAnalyzer(args.provider)
        
        # Check if report file exists when needed
        if not args.history_only and not args.flow_only and not args.suspicious_only:
            if not os.path.exists(args.report):
                print(f"[X] Vulnerability report not found: {args.report}")
                print(f"[*] Continuing with limited analysis...")
        
        # Run specified analyses or full report
        if args.history_only:
            analyzer.analyze_contract_history(args.contract)
        elif args.suspicious_only:
            analyzer.identify_suspicious_actors(args.contract)
        elif args.flow_only:
            analyzer.trace_funds_flow(args.contract, depth=args.depth)
        elif args.attack_only:
            analyzer.reconstruct_attack(args.contract, args.report)
        else:
            # Run full forensic report
            analyzer.generate_forensic_report(args.contract, args.report)
        
        print("\n[✓] Forensic analysis completed!")
        print(f"[✓] Reports saved in the 'forensics' directory")
        
    except Exception as e:
        print(f"[X] Error during forensic analysis: {e}")
        import traceback
        print(traceback.format_exc())
        return 1
    
    return 0

if __name__ == "__main__":
    main() 