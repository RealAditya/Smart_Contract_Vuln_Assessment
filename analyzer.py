import subprocess
import json
import os

# Folder path containing the smart contracts to analyze
CONTRACTS_FOLDER = "contracts"
REPORTS_FOLDER = "reports"

# Ensure reports folder exists
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# Run Mythril for security analysis
def run_mythril(contract_path):
    print(f"[*] Running Mythril analysis on {contract_path}...")
    
    try:
        # Run Mythril and capture the output (text format)
        result = subprocess.run(
            ['myth', 'analyze', contract_path, '--execution-timeout', '30'],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            print(f"[X] Mythril error: {result.stderr}")
            return None

        return result.stdout.strip()  # Return cleaned output
    
    except Exception as e:
        print(f"[X] Error running Mythril: {e}")
        return None

# Run Slither for security analysis
def run_slither(contract_path, contract_name):
    print(f"[*] Running Slither analysis on {contract_path}...")
    
    try:
        slither_report_file = os.path.join(REPORTS_FOLDER, f'slither_{contract_name}.json')
        
        # Run Slither and capture output in JSON
        result = subprocess.run(
            ['slither', contract_path, '--json', slither_report_file],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            print(f"[X] Slither error: {result.stderr}")
            return None
        
        with open(slither_report_file, 'r') as f:
            slither_output = json.load(f)

        os.remove(slither_report_file)  # Cleanup after use
        return slither_output
    
    except Exception as e:
        print(f"[X] Error running Slither: {e}")
        return None

# Generate and store individual reports per contract
def save_contract_report(contract_name, analysis_result):
    report_file = os.path.join(REPORTS_FOLDER, f"{contract_name}_report.json")
    
    with open(report_file, 'w') as f:
        json.dump(analysis_result, f, indent=4)
    
    print(f"[✓] Security report saved: {report_file}")

if __name__ == "__main__":
    analysis_results = []
    
    for contract_file in os.listdir(CONTRACTS_FOLDER):
        if contract_file.endswith(".sol"):
            contract_path = os.path.join(CONTRACTS_FOLDER, contract_file)
            contract_name = contract_file.split('.')[0]

            print(f"\n[===] Analyzing Contract: {contract_file} [===]")

            # Step 1: Run Mythril
            mythril_result = run_mythril(contract_path)
            
            # Step 2: Run Slither
            slither_result = run_slither(contract_path, contract_name)
            
            # Step 3: Store results
            if mythril_result or slither_result:
                result_data = {
                    'contract': contract_file,
                    'mythril_analysis': mythril_result if mythril_result else "Mythril analysis failed",
                    'slither_analysis': slither_result if slither_result else "Slither analysis failed"
                }
                save_contract_report(contract_name, result_data)
                analysis_results.append(result_data)
            else:
                print(f"[X] Analysis failed for contract: {contract_file}")

    if analysis_results:
        print("\n[✓] All analyses completed. Reports saved in the 'reports' folder.")
    else:
        print("\n[X] No analysis results to report. Check the analysis process.")
