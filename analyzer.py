import subprocess
import json
import os
import time
import traceback
import sys

# Folder path containing the smart contracts to analyze
CONTRACTS_FOLDER = "contracts"
REPORTS_FOLDER = "reports"

# Ensure reports folder exists
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# Run Mythril for security analysis
def run_mythril(contract_path):
    print(f"[*] Running Mythril analysis on {contract_path}...")
    
    try:
        # Print command for debugging
        cmd = ['myth', 'analyze', contract_path, '--execution-timeout', '60', '-o', 'json']
        print(f"[DEBUG] Running command: {' '.join(cmd)}")
        
        # Run Mythril and capture the output
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=120  # Increase timeout for analysis
        )
        
        # Print exit code for debugging
        print(f"[DEBUG] Mythril exit code: {result.returncode}")
        
        # Even if returncode is non-zero, Mythril might still provide useful output
        if result.stdout:
            print(f"[DEBUG] Mythril output length: {len(result.stdout)} characters")
            try:
                # Try to parse as JSON
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                print(f"[DEBUG] Could not parse Mythril output as JSON, returning raw output")
                return result.stdout.strip()
        else:
            print(f"[X] Mythril error: {result.stderr}")
            return None
    
    except subprocess.TimeoutExpired:
        print(f"[X] Mythril analysis timed out on {contract_path}")
        return None
    except Exception as e:
        print(f"[X] Error running Mythril: {e}")
        print(traceback.format_exc())
        return None

# Run Slither for security analysis
def run_slither(contract_path, contract_name):
    print(f"[*] Running Slither analysis on {contract_path}...")
    
    try:
        slither_report_file = os.path.join(REPORTS_FOLDER, f'slither_{contract_name}.json')
        
        # Force overwrite any existing slither report
        if os.path.exists(slither_report_file):
            os.remove(slither_report_file)
        
        # Run Slither and capture output in JSON
        result = subprocess.run(
            ['slither', contract_path, '--json', slither_report_file],
            capture_output=True, text=True, timeout=60
        )
        
        # Even if Slither returns a non-zero exit code, it often still produces a valid report
        if os.path.exists(slither_report_file):
            try:
                with open(slither_report_file, 'r') as f:
                    slither_output = json.load(f)
                
                # Keep the file for reference
                return slither_output
            except json.JSONDecodeError:
                print(f"[X] Slither generated an invalid JSON file: {slither_report_file}")
                
        print(f"[X] Slither error or no report generated: {result.stderr}")
        return None
    
    except subprocess.TimeoutExpired:
        print(f"[X] Slither analysis timed out on {contract_path}")
        return None
    except Exception as e:
        print(f"[X] Error running Slither: {e}")
        print(traceback.format_exc())
        return None

# Generate and store individual reports per contract
def save_contract_report(contract_name, analysis_result):
    report_file = os.path.join(REPORTS_FOLDER, f"{contract_name}_report.json")
    
    # Force overwrite any existing report
    with open(report_file, 'w') as f:
        json.dump(analysis_result, f, indent=4)
    
    print(f"[✓] Security report saved: {report_file}")

if __name__ == "__main__":
    analysis_results = []
    
    for contract_file in os.listdir(CONTRACTS_FOLDER):
        if contract_file.endswith(".sol"):
            contract_path = os.path.join(CONTRACTS_FOLDER, contract_file)
            # Remove spaces from contract name for file naming
            contract_name = contract_file.split('.')[0].replace(" ", "_") 

            print(f"\n[===] Analyzing Contract: {contract_file} [===]")

            # Step 1: Run Mythril
            mythril_result = run_mythril(contract_path)
            
            # Step 2: Run Slither
            slither_result = run_slither(contract_path, contract_name)
            
            # Step 3: Store results
            result_data = {
                'contract': contract_file,
                'mythril_analysis': mythril_result if mythril_result else "Mythril analysis failed",
                'slither_analysis': slither_result if slither_result else "Slither analysis failed"
            }
            
            save_contract_report(contract_name, result_data)
            analysis_results.append(result_data)
            
            # Small delay to avoid overwhelming system resources
            time.sleep(1)

    if analysis_results:
        print("\n[✓] All analyses completed. Reports saved in the 'reports' folder.")
    else:
        print("\n[X] No analysis results to report. Check the analysis process.")
