#!/usr/bin/env python3
import os
import json
import subprocess
from datetime import datetime
import argparse
# from forensics import ForensicAnalyzer
from run_forensics import SimpleForensicAnalyzer

# Constants
REPORTS_FOLDER = "reports"
CONTRACTS_FOLDER = "contracts"
CONSOLIDATED_REPORT_FILE = "consolidated_security_report.json"
CONSOLIDATED_REPORT_HTML = "consolidated_security_report.html"

def run_analyzer():
    """Run the analyzer.py to generate/update individual reports"""
    print("[*] Running analyzer to generate individual contract reports...")
    try:
        result = subprocess.run(['python3', 'analyzer.py'], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[X] Error running analyzer: {result.stderr}")
            return False
        print(result.stdout)
        return True
    except Exception as e:
        print(f"[X] Error executing analyzer.py: {e}")
        return False

def collect_contract_reports():
    """Collect all individual contract reports and Slither analysis"""
    contract_reports = []
    
    print("[*] Collecting individual contract reports...")
    
    # First collect contract report files
    for filename in os.listdir(REPORTS_FOLDER):
        if filename.endswith("_report.json"):
            report_path = os.path.join(REPORTS_FOLDER, filename)
            try:
                with open(report_path, 'r') as f:
                    report_data = json.load(f)
                    
                    # Get contract name without underscores
                    contract_name = report_data['contract']
                    
                    # Check if a corresponding Slither report exists
                    contract_base = filename.split('_report.json')[0]
                    slither_file = f"slither_{contract_base}.json"
                    slither_path = os.path.join(REPORTS_FOLDER, slither_file)
                    
                    # If Slither report exists, read it directly instead of using the one in report_data
                    if os.path.exists(slither_path):
                        try:
                            with open(slither_path, 'r') as sf:
                                slither_data = json.load(sf)
                                report_data['slither_analysis'] = slither_data
                        except Exception as e:
                            print(f"[X] Error reading Slither report {slither_file}: {e}")
                    
                    contract_reports.append(report_data)
                    print(f"[✓] Collected report for {report_data['contract']}")
            except Exception as e:
                print(f"[X] Error reading report {filename}: {e}")
    
    return contract_reports

def generate_consolidated_report(contract_reports):
    """Generate a consolidated JSON report from individual reports"""
    if not contract_reports:
        print("[X] No contract reports found!")
        return False
    
    print(f"[*] Generating consolidated report from {len(contract_reports)} contracts...")
    
    consolidated_data = {
        "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_contracts_analyzed": len(contract_reports),
        "contracts": []
    }
    
    vulnerability_summary = {}
    
    # Process each contract
    for report in contract_reports:
        contract_name = report["contract"]
        contract_data = {
            "name": contract_name,
            "vulnerabilities": []
        }
        
        # Process Mythril results
        if report["mythril_analysis"] and report["mythril_analysis"] != "Mythril analysis failed":
            mythril_result = report["mythril_analysis"]
            
            # Check if Mythril result is already in JSON format
            if isinstance(mythril_result, dict) and "issues" in mythril_result:
                # Process JSON output
                for issue in mythril_result.get("issues", []):
                    # Handle different formats of description
                    if isinstance(issue.get("description"), dict):
                        description = issue.get("description", {}).get("head", "") + ": " + issue.get("description", {}).get("tail", "")
                    else:
                        description = issue.get("description", "No description provided")
                        
                    vulnerability = {
                        "tool": "Mythril",
                        "title": issue.get("title", "Unknown"),
                        "severity": issue.get("severity", "Unknown"),
                        "description": description
                    }
                    contract_data["vulnerabilities"].append(vulnerability)
                    
                    # Add to summary
                    key = f"{vulnerability['title']} ({vulnerability['severity']})"
                    vulnerability_summary[key] = vulnerability_summary.get(key, 0) + 1
            else:
                # Process text output
                mythril_issues = extract_mythril_issues(mythril_result)
                for issue in mythril_issues:
                    vulnerability = {
                        "tool": "Mythril",
                        "title": issue["title"],
                        "severity": issue["severity"],
                        "description": issue["description"]
                    }
                    contract_data["vulnerabilities"].append(vulnerability)
                    
                    # Add to summary
                    key = f"{issue['title']} ({issue['severity']})"
                    vulnerability_summary[key] = vulnerability_summary.get(key, 0) + 1
        
        # Process Slither results
        if report["slither_analysis"] and report["slither_analysis"] != "Slither analysis failed":
            slither_data = report["slither_analysis"]
            
            if isinstance(slither_data, dict) and "results" in slither_data and "detectors" in slither_data["results"]:
                for issue in slither_data["results"]["detectors"]:
                    # Extract meaningful description
                    description = issue.get("description", "No description provided")
                    
                    # Get the check name
                    check = issue.get("check", "Unknown")
                    
                    # Map Slither impact to severity
                    impact_to_severity = {
                        "High": "High",
                        "Medium": "Medium",
                        "Low": "Low",
                        "Informational": "Informational"
                    }
                    severity = impact_to_severity.get(issue.get("impact", "Unknown"), "Unknown")
                    
                    vulnerability = {
                        "tool": "Slither",
                        "title": check,
                        "severity": severity,
                        "description": description
                    }
                    contract_data["vulnerabilities"].append(vulnerability)
                    
                    # Add to summary
                    key = f"{check} ({severity})"
                    vulnerability_summary[key] = vulnerability_summary.get(key, 0) + 1
        
        consolidated_data["contracts"].append(contract_data)
    
    # Sort vulnerabilities by count (descending)
    consolidated_data["vulnerability_summary"] = [
        {"vulnerability": vuln, "count": count}
        for vuln, count in sorted(vulnerability_summary.items(), key=lambda x: x[1], reverse=True)
    ]
    
    # Write to file
    with open(CONSOLIDATED_REPORT_FILE, 'w') as f:
        json.dump(consolidated_data, f, indent=4)
    
    print(f"[✓] Consolidated JSON report saved: {CONSOLIDATED_REPORT_FILE}")
    return consolidated_data

def extract_mythril_issues(mythril_text):
    """Extract vulnerability issues from Mythril plain text output"""
    issues = []
    
    # Simple parsing of Mythril output
    if isinstance(mythril_text, str):
        if "The analysis was completed successfully" in mythril_text:
            # Split by sections that indicate new findings
            sections = mythril_text.split("==== ")
            
            for section in sections:
                if ":" in section and len(section) > 10:  # Simple heuristic to identify issue sections
                    lines = section.strip().split("\n")
                    if lines:
                        title_line = lines[0]
                        title = title_line.split(":", 1)[0] if ":" in title_line else "Unknown issue"
                        
                        # Try to extract severity
                        severity = "Unknown"
                        for line in lines:
                            if "Severity:" in line:
                                severity = line.split("Severity:", 1)[1].strip()
                                break
                        
                        # Join the rest as description
                        description = "\n".join(lines[1:])
                        
                        issues.append({
                            "title": title,
                            "severity": severity,
                            "description": description
                        })
    
    return issues

def generate_html_report(consolidated_data):
    """Generate an HTML report from the consolidated data"""
    print("[*] Generating HTML report...")
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Contract Security Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .header {{ background-color: #3498db; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .contract {{ background-color: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; }}
        .vulnerability {{ border-left: 4px solid #ddd; padding: 10px; margin: 10px 0; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #e67e22; }}
        .medium {{ border-left-color: #f1c40f; }}
        .low {{ border-left-color: #3498db; }}
        .informational {{ border-left-color: #95a5a6; }}
        .severity {{ display: inline-block; padding: 3px 6px; border-radius: 3px; font-size: 12px; font-weight: bold; color: white; }}
        .severity.critical {{ background-color: #e74c3c; }}
        .severity.high {{ background-color: #e67e22; }}
        .severity.medium {{ background-color: #f1c40f; color: #333; }}
        .severity.low {{ background-color: #3498db; }}
        .severity.informational {{ background-color: #95a5a6; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        .summary-count {{ text-align: center; }}
        .toc {{ margin-bottom: 20px; }}
        .toc a {{ color: #3498db; text-decoration: none; }}
        .toc a:hover {{ text-decoration: underline; }}
        footer {{ margin-top: 30px; text-align: center; font-size: 0.8em; color: #777; }}
        pre {{ white-space: pre-wrap; background-color: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Smart Contract Security Analysis Report</h1>
            <p>Report generated on: {consolidated_data["report_date"]}</p>
            <p>Total contracts analyzed: {consolidated_data["total_contracts_analyzed"]}</p>
        </div>

        <div class="toc">
            <h2>Table of Contents</h2>
            <ol>
                <li><a href="#summary">Vulnerability Summary</a></li>
                <li><a href="#contracts">Contract Details</a>
                    <ul>
"""

    # Add TOC entries for each contract
    for i, contract in enumerate(consolidated_data["contracts"]):
        html_content += f"""                        <li><a href="#contract-{i}">{contract["name"]}</a></li>
"""

    html_content += """                    </ul>
                </li>
            </ol>
        </div>

        <div id="summary" class="summary">
            <h2>Vulnerability Summary</h2>
"""

    if not consolidated_data["vulnerability_summary"]:
        html_content += """            <p>No vulnerabilities were found.</p>
"""
    else:
        html_content += """            <table>
                <tr>
                    <th>Vulnerability</th>
                    <th>Count</th>
                </tr>
"""

        # Add vulnerability summary table
        for vuln in consolidated_data["vulnerability_summary"]:
            html_content += f"""
                <tr>
                    <td>{vuln["vulnerability"]}</td>
                    <td class="summary-count">{vuln["count"]}</td>
                </tr>"""

        html_content += """
            </table>
"""

    html_content += """
        </div>

        <h2 id="contracts">Contract Details</h2>
"""

    # Add details for each contract
    for i, contract in enumerate(consolidated_data["contracts"]):
        html_content += f"""
        <div id="contract-{i}" class="contract">
            <h3>{contract["name"]}</h3>
            <p>Total vulnerabilities: {len(contract["vulnerabilities"])}</p>
"""

        if not contract["vulnerabilities"]:
            html_content += """
            <p>No vulnerabilities found in this contract.</p>
"""
        else:
            # Group vulnerabilities by tool
            tools = {}
            for vuln in contract["vulnerabilities"]:
                tool = vuln["tool"]
                if tool not in tools:
                    tools[tool] = []
                tools[tool].append(vuln)
            
            # Display vulnerabilities grouped by tool
            for tool, vulns in tools.items():
                html_content += f"""
            <h4>{tool} Findings ({len(vulns)})</h4>
"""
                
                # Sort vulnerabilities by severity
                severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4, "Unknown": 5}
                sorted_vulns = sorted(vulns, 
                    key=lambda x: severity_order.get(x["severity"].capitalize(), 9))
                
                for vuln in sorted_vulns:
                    # Determine severity class
                    severity_class = vuln["severity"].lower()
                    if severity_class not in ["critical", "high", "medium", "low", "informational"]:
                        severity_class = "low"  # Default
                    
                    html_content += f"""
            <div class="vulnerability {severity_class}">
                <h4>{vuln["title"]} <span class="severity {severity_class}">{vuln["severity"]}</span></h4>
                <pre>{vuln["description"]}</pre>
            </div>
"""

        html_content += """
        </div>
"""

    html_content += """
        <footer>
            <p>This report was generated by the Smart Contract Security Analysis tool.</p>
        </footer>
    </div>
</body>
</html>
"""

    with open(CONSOLIDATED_REPORT_HTML, 'w') as f:
        f.write(html_content)
    
    print(f"[✓] HTML report saved: {CONSOLIDATED_REPORT_HTML}")
    return True

def main():
    """Main function to run the entire analysis pipeline"""
    parser = argparse.ArgumentParser(description='Generate consolidated security report for smart contracts')
    parser.add_argument('--forensics', action='store_true', help='Run forensic analysis after security report generation')
    args = parser.parse_args()
    
    # Step 1: Run analyzer to generate individual reports
    if not run_analyzer():
        print("[X] Failed to generate individual reports")
        return
    
    # Step 2: Collect all contract reports
    contract_reports = collect_contract_reports()
    if not contract_reports:
        print("[X] No contract reports found!")
        return
    
    # Step 3: Generate consolidated report
    consolidated_data = generate_consolidated_report(contract_reports)
    if not consolidated_data:
        print("[X] Failed to generate consolidated report")
        return
    
    # Step 4: Generate HTML report
    if not generate_html_report(consolidated_data):
        print("[X] Failed to generate HTML report")
        return
    
    # Step 5: Run forensic analysis if requested
    if args.forensics:
        print("\n[*] Running forensic analysis...")
        try:
            from run_forensic_analysis import main as run_forensics
            run_forensics()
            print("[✓] Forensic analysis completed")
        except Exception as e:
            print(f"[X] Error during forensic analysis: {e}")
    
    print("\n[✓] Analysis completed successfully!")
    print(f"[*] Consolidated JSON report: {CONSOLIDATED_REPORT_FILE}")
    print(f"[*] HTML report: {CONSOLIDATED_REPORT_HTML}")
    if args.forensics:
        print("[*] Forensic analysis results: forensics/")

if __name__ == "__main__":
    main() 