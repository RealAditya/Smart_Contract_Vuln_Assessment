#!/usr/bin/env python3

import os
import json
import time
import random
import datetime
from collections import defaultdict

# Constants
FORENSICS_FOLDER = "forensics"
MAX_TRANSACTIONS = 100
SIMULATION_BLOCKS = 1000
TRANSACTION_TYPES = ["transfer", "call", "delegatecall", "staticcall"]
ADDRESS_PREFIXES = ["0x1", "0x2", "0x3", "0x4", "0x5", "0x6", "0x7", "0x8", "0x9", "0xa", "0xb", "0xc", "0xd", "0xe", "0xf"]

# Ensure forensics folder exists
os.makedirs(FORENSICS_FOLDER, exist_ok=True)

class SimpleForensicAnalyzer:
    """A simplified blockchain forensic analysis tool without external dependencies."""
    
    def __init__(self, provider_url=None):
        """Initialize the forensic analyzer with a simulation engine"""
        self.provider_url = provider_url
        print(f"[*] Initializing forensic analyzer in simulation mode")
        
        # Create a simulation log
        with open(os.path.join(FORENSICS_FOLDER, "simulation_info.txt"), "w") as f:
            f.write(f"Simulation started: {datetime.datetime.now()}\n")
            f.write(f"Using simulated blockchain data instead of Web3\n")
    
    def _generate_address(self, seed=None):
        """Generate a random Ethereum-like address"""
        if seed:
            random.seed(seed)
        prefix = random.choice(ADDRESS_PREFIXES)
        suffix = ''.join(random.choice("0123456789abcdef") for _ in range(38))
        return prefix + suffix
    
    def _generate_transaction_hash(self):
        """Generate a random transaction hash"""
        return "0x" + ''.join(random.choice("0123456789abcdef") for _ in range(64))
    
    def _generate_simulated_transactions(self, contract_address, num_transactions=50):
        """Generate simulated transactions for the contract"""
        transactions = []
        
        # Generate a set of accounts that interact with the contract
        accounts = [self._generate_address(i) for i in range(10)]
        attacker_account = self._generate_address("attacker")
        
        # Add the attacker account to the set of accounts
        accounts.append(attacker_account)
        
        # Generate transactions
        block_number = SIMULATION_BLOCKS - num_transactions
        timestamp_base = int(time.time()) - (num_transactions * 15)  # Assuming 15 seconds per block
        
        for i in range(num_transactions):
            # Select sender and value
            sender = random.choice(accounts)
            value = random.randint(0, 1000000000000000000)  # Between 0 and 1 ETH
            
            # Make the attacker account more likely to be involved in suspicious transactions
            if sender == attacker_account or random.random() < 0.2:
                gas_used = random.randint(900000, 1000000)  # High gas usage
                transaction_type = random.choice(["call", "delegatecall"])  # More dangerous call types
                is_error = random.random() < 0.3  # Higher chance of errors
            else:
                gas_used = random.randint(21000, 100000)  # Normal gas usage
                transaction_type = random.choice(TRANSACTION_TYPES)
                is_error = random.random() < 0.05  # Lower chance of errors
            
            # Create the transaction
            transaction = {
                "hash": self._generate_transaction_hash(),
                "from": sender,
                "to": contract_address,
                "value": value,
                "gasUsed": gas_used,
                "blockNumber": block_number + i,
                "timestamp": timestamp_base + (i * 15),
                "type": transaction_type,
                "isError": 1 if is_error else 0
            }
            
            transactions.append(transaction)
        
        return transactions, accounts, attacker_account
    
    def analyze_contract_history(self, contract_address, max_blocks=1000):
        """Analyze transaction history for a contract (simulation)"""
        print(f"[*] Analyzing contract history for {contract_address}")
        
        # Generate simulated transactions
        transactions, accounts, attacker = self._generate_simulated_transactions(contract_address)
        
        # Save the transactions to a file
        history_file = os.path.join(FORENSICS_FOLDER, f"{contract_address[:10]}_history.json")
        with open(history_file, "w") as f:
            json.dump({
                "contract": contract_address,
                "transactions": transactions,
                "analysis_date": datetime.datetime.now().isoformat(),
                "summary": {
                    "total_transactions": len(transactions),
                    "total_accounts_interacted": len(accounts),
                    "earliest_block": transactions[0]["blockNumber"],
                    "latest_block": transactions[-1]["blockNumber"],
                    "high_value_transactions": sum(1 for tx in transactions if tx["value"] > 500000000000000000),
                    "error_transactions": sum(1 for tx in transactions if tx["isError"] == 1)
                }
            }, f, indent=4)
        
        print(f"[✓] Contract history analysis saved to {history_file}")
        return history_file
    
    def identify_suspicious_actors(self, contract_address):
        """Identify potentially suspicious actors interacting with the contract (simulation)"""
        print(f"[*] Identifying suspicious actors for {contract_address}")
        
        # Generate simulated transactions
        transactions, accounts, attacker = self._generate_simulated_transactions(contract_address, num_transactions=100)
        
        # Analyze transaction patterns for each account
        account_stats = defaultdict(lambda: {
            "transaction_count": 0,
            "total_value_sent": 0,
            "total_value_received": 0,
            "error_rate": 0,
            "high_gas_transactions": 0,
            "dangerous_calls": 0,
            "risk_score": 0
        })
        
        # Count transactions for each account
        for tx in transactions:
            sender = tx["from"]
            account_stats[sender]["transaction_count"] += 1
            account_stats[sender]["total_value_sent"] += tx["value"]
            
            if tx["isError"] == 1:
                account_stats[sender]["error_rate"] += 1
            
            if tx["gasUsed"] > 500000:
                account_stats[sender]["high_gas_transactions"] += 1
                
            if tx["type"] in ["delegatecall", "call"]:
                account_stats[sender]["dangerous_calls"] += 1
        
        # Calculate risk scores
        suspicious_actors = []
        for account, stats in account_stats.items():
            if stats["transaction_count"] > 0:
                stats["error_rate"] = stats["error_rate"] / stats["transaction_count"]
                
                # Calculate risk score based on various factors
                risk_score = (
                    min(1.0, stats["dangerous_calls"] / max(1, stats["transaction_count"])) * 40 +
                    min(1.0, stats["high_gas_transactions"] / max(1, stats["transaction_count"])) * 30 +
                    stats["error_rate"] * 20 +
                    min(1.0, stats["total_value_sent"] / 1000000000000000000) * 10  # Normalize by 1 ETH
                )
                
                stats["risk_score"] = risk_score
                stats["address"] = account
                
                # Consider high risk if score > 30
                if risk_score > 30:
                    suspicious_actors.append(stats)
        
        # Sort suspicious actors by risk score (highest first)
        suspicious_actors.sort(key=lambda x: x["risk_score"], reverse=True)
        
        # Save the suspicious actors report
        actors_file = os.path.join(FORENSICS_FOLDER, f"{contract_address[:10]}_suspicious_actors.json")
        with open(actors_file, "w") as f:
            json.dump({
                "contract": contract_address,
                "analysis_date": datetime.datetime.now().isoformat(),
                "suspicious_actors": suspicious_actors,
                "total_accounts_analyzed": len(account_stats),
                "high_risk_threshold": 30,
                "note": "This is simulated data for demonstration purposes"
            }, f, indent=4)
        
        print(f"[✓] Suspicious actors analysis saved to {actors_file}")
        return actors_file
    
    def reconstruct_attack(self, contract_address, vulnerability_report=None):
        """Reconstruct potential attack scenarios based on vulnerabilities (simulation)"""
        print(f"[*] Reconstructing potential attacks for {contract_address}")
        
        vulnerabilities = []
        if vulnerability_report and os.path.exists(vulnerability_report):
            try:
                with open(vulnerability_report, 'r') as f:
                    report_data = json.load(f)
                    
                    # Find vulnerabilities for the specific contract
                    for contract in report_data.get("contracts", []):
                        if contract.get("name", "").split(".")[0].lower() in contract_address.lower():
                            vulnerabilities = contract.get("vulnerabilities", [])
                            break
            except Exception as e:
                print(f"[X] Error reading vulnerability report: {e}")
                # Continue with empty vulnerabilities list
        
        # Generate simulated transactions and the attacker
        transactions, accounts, attacker = self._generate_simulated_transactions(contract_address)
        
        # Create attack scenarios based on vulnerabilities
        attack_scenarios = []
        
        # Map vulnerability types to attack patterns
        vulnerability_to_attack = {
            "reentrancy": {
                "name": "Reentrancy Attack",
                "pattern": "Multiple rapid calls from same address before state update",
                "simulation": [
                    {"timestamp": int(time.time()) - 1000, "from": attacker, "to": contract_address, "value": 100000000000000000, "type": "call", "gas": 100000},
                    {"timestamp": int(time.time()) - 995, "from": attacker, "to": contract_address, "value": 0, "type": "call", "gas": 500000},
                    {"timestamp": int(time.time()) - 994, "from": contract_address, "to": attacker, "value": 200000000000000000, "type": "call", "gas": 30000},
                    {"timestamp": int(time.time()) - 993, "from": attacker, "to": contract_address, "value": 0, "type": "call", "gas": 500000},
                    {"timestamp": int(time.time()) - 992, "from": contract_address, "to": attacker, "value": 200000000000000000, "type": "call", "gas": 30000}
                ]
            },
            "unchecked-send": {
                "name": "Failed Transfer Exploitation",
                "pattern": "Exploiting unchecked return values from send/call",
                "simulation": [
                    {"timestamp": int(time.time()) - 900, "from": attacker, "to": contract_address, "value": 50000000000000000, "type": "call", "gas": 100000},
                    {"timestamp": int(time.time()) - 890, "from": attacker, "to": contract_address, "value": 0, "type": "call", "gas": 300000, "isError": 1},
                    {"timestamp": int(time.time()) - 880, "from": attacker, "to": contract_address, "value": 0, "type": "call", "gas": 300000},
                    {"timestamp": int(time.time()) - 870, "from": contract_address, "to": attacker, "value": 1000000000000000000, "type": "call", "gas": 30000}
                ]
            },
            "access-control": {
                "name": "Unauthorized Access",
                "pattern": "Exploiting missing or inadequate access controls",
                "simulation": [
                    {"timestamp": int(time.time()) - 800, "from": attacker, "to": contract_address, "value": 0, "type": "call", "gas": 200000},
                    {"timestamp": int(time.time()) - 790, "from": contract_address, "to": attacker, "value": 2000000000000000000, "type": "call", "gas": 30000}
                ]
            },
            "front-running": {
                "name": "Transaction Order Manipulation",
                "pattern": "Front-running transactions to gain advantage",
                "simulation": [
                    {"timestamp": int(time.time()) - 700, "from": accounts[0], "to": contract_address, "value": 0, "type": "call", "gas": 100000, "gasPrice": 2000000000},
                    {"timestamp": int(time.time()) - 699, "from": attacker, "to": contract_address, "value": 0, "type": "call", "gas": 150000, "gasPrice": 5000000000},
                    {"timestamp": int(time.time()) - 698, "from": contract_address, "to": attacker, "value": 500000000000000000, "type": "call", "gas": 30000}
                ]
            }
        }
        
        # Map real vulnerability types from report to our attack patterns
        for vuln in vulnerabilities:
            vuln_type = vuln.get("title", "").lower()
            
            if "reentrancy" in vuln_type:
                attack_type = "reentrancy"
            elif "unchecked" in vuln_type or "return value" in vuln_type:
                attack_type = "unchecked-send"
            elif "access" in vuln_type or "authorization" in vuln_type or "permission" in vuln_type:
                attack_type = "access-control"
            elif "order" in vuln_type or "front" in vuln_type:
                attack_type = "front-running"
            else:
                continue  # Skip unmapped vulnerabilities
            
            # Add the attack scenario
            attack_info = vulnerability_to_attack.get(attack_type)
            if attack_info:
                scenario = {
                    "vulnerability": vuln,
                    "attack_name": attack_info["name"],
                    "attack_pattern": attack_info["pattern"],
                    "likelihood": "High" if vuln.get("severity") in ["High", "Critical"] else "Medium",
                    "potential_transactions": attack_info["simulation"],
                    "mitigation": f"Fix the {vuln_type} vulnerability by implementing proper checks and state management"
                }
                attack_scenarios.append(scenario)
        
        # If no vulnerabilities were mapped, add a generic attack scenario
        if not attack_scenarios:
            attack_scenarios.append({
                "vulnerability": {"title": "Unknown Vulnerability", "severity": "Medium"},
                "attack_name": "Generic Contract Exploitation",
                "attack_pattern": "Unusual transaction patterns suggesting exploitation",
                "likelihood": "Medium",
                "potential_transactions": vulnerability_to_attack["reentrancy"]["simulation"],
                "mitigation": "Perform a comprehensive security audit to identify specific vulnerabilities"
            })
        
        # Save the attack reconstruction report
        reconstruction_file = os.path.join(FORENSICS_FOLDER, f"{contract_address[:10]}_attack_reconstruction.json")
        with open(reconstruction_file, "w") as f:
            json.dump({
                "contract": contract_address,
                "analysis_date": datetime.datetime.now().isoformat(),
                "vulnerabilities_analyzed": len(vulnerabilities),
                "attack_scenarios": attack_scenarios,
                "note": "This is simulated data for demonstration purposes. Real attacks may vary."
            }, f, indent=4)
        
        print(f"[✓] Attack reconstruction saved to {reconstruction_file}")
        return reconstruction_file
    
    def generate_forensic_report(self, contract_address, vulnerability_report=None):
        """Generate a comprehensive forensic report for a contract"""
        print(f"[===] Generating comprehensive forensic report for {contract_address} [===]")
        
        # Create forensic report directory
        report_dir = os.path.join(FORENSICS_FOLDER, f"{contract_address[:10]}_forensic_report")
        os.makedirs(report_dir, exist_ok=True)
        
        # Run all analyses
        history_file = self.analyze_contract_history(contract_address)
        actors_file = self.identify_suspicious_actors(contract_address)
        reconstruction_file = self.reconstruct_attack(contract_address, vulnerability_report)
        
        # Collect all analysis results
        try:
            with open(history_file, 'r') as f:
                history_data = json.load(f)
                
            with open(actors_file, 'r') as f:
                actors_data = json.load(f)
                
            with open(reconstruction_file, 'r') as f:
                reconstruction_data = json.load(f)
                
            # Generate consolidated report
            report_data = {
                "contract_address": contract_address,
                "report_date": datetime.datetime.now().isoformat(),
                "transaction_history": history_data,
                "suspicious_actors": actors_data,
                "attack_reconstruction": reconstruction_data,
                "executive_summary": {
                    "total_transactions": history_data["summary"]["total_transactions"],
                    "total_accounts": history_data["summary"]["total_accounts_interacted"],
                    "suspicious_accounts": len(actors_data["suspicious_actors"]),
                    "attack_scenarios": len(reconstruction_data["attack_scenarios"]),
                    "risk_assessment": "High" if len(reconstruction_data["attack_scenarios"]) > 0 and 
                                        any(s["likelihood"] == "High" for s in reconstruction_data["attack_scenarios"]) 
                                      else "Medium" if len(reconstruction_data["attack_scenarios"]) > 0 
                                      else "Low"
                }
            }
            
            # Save the consolidated report
            consolidated_file = os.path.join(report_dir, "forensic_report.json")
            with open(consolidated_file, 'w') as f:
                json.dump(report_data, f, indent=4)
                
            # Generate HTML report
            self._generate_html_report(report_data, report_dir)
                
            print(f"[✓] Comprehensive forensic report generated in {report_dir}")
            return consolidated_file
            
        except Exception as e:
            print(f"[X] Error generating consolidated report: {e}")
            import traceback
            print(traceback.format_exc())
            return None
    
    def _generate_html_report(self, report_data, report_dir):
        """Generate HTML report from the consolidated JSON report"""
        
        # Create basic HTML structure
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blockchain Forensic Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; color: #333; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .section {{ background-color: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1, h2, h3 {{ color: #2c3e50; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .risk-high {{ color: #e74c3c; font-weight: bold; }}
        .risk-medium {{ color: #e67e22; font-weight: bold; }}
        .risk-low {{ color: #2ecc71; font-weight: bold; }}
        .suspicious-actor {{ background-color: #ffeeee; }}
        .attack-scenario {{ background-color: #fff6e6; padding: 15px; margin: 10px 0; border-left: 4px solid #e67e22; }}
        footer {{ text-align: center; margin-top: 30px; color: #7f8c8d; font-size: 0.8em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Blockchain Forensic Analysis Report</h1>
            <p>Contract Address: {report_data['contract_address']}</p>
            <p>Report Generated: {report_data['report_date']}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <table>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Total Transactions Analyzed</td>
                    <td>{report_data['executive_summary']['total_transactions']}</td>
                </tr>
                <tr>
                    <td>Total Accounts Interacting</td>
                    <td>{report_data['executive_summary']['total_accounts']}</td>
                </tr>
                <tr>
                    <td>Suspicious Accounts Identified</td>
                    <td>{report_data['executive_summary']['suspicious_accounts']}</td>
                </tr>
                <tr>
                    <td>Potential Attack Scenarios</td>
                    <td>{report_data['executive_summary']['attack_scenarios']}</td>
                </tr>
                <tr>
                    <td>Overall Risk Assessment</td>
                    <td class="risk-{report_data['executive_summary']['risk_assessment'].lower()}">{report_data['executive_summary']['risk_assessment']}</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Transaction History Analysis</h2>
            <p>Analysis of {report_data['transaction_history']['summary']['total_transactions']} transactions reveals the following patterns:</p>
            <ul>
                <li>Total number of accounts interacting with contract: {report_data['transaction_history']['summary']['total_accounts_interacted']}</li>
                <li>High-value transactions: {report_data['transaction_history']['summary']['high_value_transactions']}</li>
                <li>Failed transactions: {report_data['transaction_history']['summary']['error_transactions']}</li>
                <li>Block range: {report_data['transaction_history']['summary']['earliest_block']} to {report_data['transaction_history']['summary']['latest_block']}</li>
            </ul>
            
            <h3>Sample Transaction Data:</h3>
            <table>
                <tr>
                    <th>Block</th>
                    <th>From</th>
                    <th>Value (Wei)</th>
                    <th>Type</th>
                    <th>Status</th>
                </tr>
        """
        
        # Add sample transaction rows (show first 5)
        for i, tx in enumerate(report_data['transaction_history']['transactions'][:5]):
            html_content += f"""
                <tr>
                    <td>{tx['blockNumber']}</td>
                    <td>{tx['from'][:10]}...</td>
                    <td>{tx['value']}</td>
                    <td>{tx['type']}</td>
                    <td>{"Failed" if tx['isError'] == 1 else "Success"}</td>
                </tr>"""
        
        html_content += """
            </table>
            <p><em>Note: Only showing first 5 transactions for brevity.</em></p>
        </div>
        
        <div class="section">
            <h2>Suspicious Actors</h2>
            <p>The following accounts showed suspicious patterns when interacting with the contract:</p>
            
            <table>
                <tr>
                    <th>Address</th>
                    <th>Risk Score</th>
                    <th>Transaction Count</th>
                    <th>Error Rate</th>
                    <th>High Gas Usage</th>
                    <th>Dangerous Calls</th>
                </tr>
        """
        
        # Add rows for suspicious actors
        for actor in report_data['suspicious_actors'].get('suspicious_actors', []):
            risk_class = "high" if actor['risk_score'] > 70 else "medium" if actor['risk_score'] > 40 else "low"
            html_content += f"""
                <tr class="suspicious-actor">
                    <td>{actor['address'][:10]}...</td>
                    <td class="risk-{risk_class}">{actor['risk_score']:.1f}</td>
                    <td>{actor['transaction_count']}</td>
                    <td>{actor['error_rate']:.2f}</td>
                    <td>{actor['high_gas_transactions']}</td>
                    <td>{actor['dangerous_calls']}</td>
                </tr>"""
        
        html_content += """
            </table>
        </div>
        
        <div class="section">
            <h2>Attack Reconstruction</h2>
            <p>Based on vulnerability analysis and transaction patterns, the following attack scenarios are possible:</p>
        """
        
        # Add attack scenarios
        for scenario in report_data['attack_reconstruction'].get('attack_scenarios', []):
            risk_class = "high" if scenario['likelihood'] == "High" else "medium" if scenario['likelihood'] == "Medium" else "low"
            
            html_content += f"""
            <div class="attack-scenario">
                <h3>{scenario['attack_name']} <span class="risk-{risk_class}">({scenario['likelihood']} Likelihood)</span></h3>
                <p><strong>Vulnerability:</strong> {scenario['vulnerability']['title']} ({scenario['vulnerability'].get('severity', 'Unknown')} severity)</p>
                <p><strong>Pattern:</strong> {scenario['attack_pattern']}</p>
                <p><strong>Mitigation:</strong> {scenario['mitigation']}</p>
                
                <h4>Representative Transaction Sequence:</h4>
                <table>
                    <tr>
                        <th>Timestamp</th>
                        <th>From</th>
                        <th>To</th>
                        <th>Value (Wei)</th>
                        <th>Type</th>
                    </tr>"""
            
            # Add transaction details
            for tx in scenario['potential_transactions']:
                html_content += f"""
                    <tr>
                        <td>{datetime.datetime.fromtimestamp(tx['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</td>
                        <td>{tx['from'][:10]}...</td>
                        <td>{tx['to'][:10]}...</td>
                        <td>{tx['value']}</td>
                        <td>{tx['type']}</td>
                    </tr>"""
            
            html_content += """
                </table>
            </div>"""
        
        # Close HTML structure
        html_content += """
        </div>
        
        <footer>
            <p>This report was generated by the Blockchain Forensic Analysis Tool. The analysis is based on simulated data for demonstration purposes.</p>
            <p>Real forensic analysis would require access to actual blockchain data and may produce different results.</p>
        </footer>
    </div>
</body>
</html>
        """
        
        # Write HTML to file
        html_file = os.path.join(report_dir, "forensic_report.html")
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        print(f"[✓] HTML forensic report generated: {html_file}")
        return html_file


if __name__ == "__main__":
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Blockchain Forensic Analysis Tool')
    parser.add_argument('--contract', '-c', type=str, required=True,
                        help='Contract address to analyze')
    parser.add_argument('--report', '-r', type=str, default='consolidated_security_report.json',
                        help='Path to vulnerability report (default: consolidated_security_report.json)')
    
    args = parser.parse_args()
    
    print("[===] Simple Blockchain Forensic Analysis Tool [===]")
    print(f"[*] Target Contract: {args.contract}")
    
    # Initialize analyzer and run analysis
    analyzer = SimpleForensicAnalyzer()
    analyzer.generate_forensic_report(args.contract, args.report) 