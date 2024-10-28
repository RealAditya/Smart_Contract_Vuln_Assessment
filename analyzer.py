import subprocess
import json
import os

# Folder path containing the smart contracts to analyze
CONTRACTS_FOLDER = os.path.join("contracts")

# Run Mythril for security analysis
def run_mythril(contract_path):
    print(f"Running Mythril analysis on {contract_path}...")
    
    try:
        # Run Mythril and capture the output without the --json flag
        result = subprocess.run(
        ['myth', 'analyze', f'"{contract_path}"', '--execution-timeout', '30'],
        capture_output=True, text=True
        )

        
        if result.returncode != 0:
            print(f"Mythril error: {result.stderr}")
            return None
        
        # Capture Mythril output (text format)
        mythril_output = result.stdout
        return mythril_output
    
    except Exception as e:
        print(f"Error running Mythril: {e}")
        return None

# Run Slither for security analysis
def run_slither(contract_path, contract_name):
    print(f"Running Slither analysis on {contract_path}...")
    
    try:
        # Create a unique Slither report file for each contract
        slither_report_file = f'slither_report_{contract_name}.json'
        
        # Run Slither and capture the output
        result = subprocess.run(
            ['slither', contract_path, '--json', slither_report_file],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            print(f"Slither error: {result.stderr}")
            return None
        
        # Load Slither's output from the unique JSON file
        with open(slither_report_file, 'r') as f:
            slither_output = json.load(f)
        return slither_output
    
    except Exception as e:
        print(f"Error running Slither: {e}")
        return None

# Generate a consolidated report with Mythril and Slither findings for each contract
def generate_report(analysis_results):
    report = {
        'contracts_analysis': analysis_results
    }
    
    # Save the report to a JSON file
    with open('report.json', 'w') as f:
        json.dump(report, f, indent=4)
    
    print("Security report generated: report.json")

if __name__ == "__main__":
    analysis_results = []
    
    # Iterate over each .sol file in the contracts folder
    for contract_file in os.listdir(CONTRACTS_FOLDER):
        if contract_file.endswith(".sol"):
            contract_path = os.path.join(CONTRACTS_FOLDER, contract_file)
            
            print(f"Analyzing contract: {contract_file}")
            
            # Step 1: Run Mythril analysis
            mythril_result = run_mythril(contract_path)
            
            # Step 2: Run Slither analysis (generate unique file per contract)
            slither_result = run_slither(contract_path, contract_file.split('.')[0])
            
            # Step 3: Store the results for this contract
            if mythril_result or slither_result:
                analysis_results.append({
                    'contract': contract_file,
                    'mythril_analysis': mythril_result if mythril_result else "Mythril analysis failed",
                    'slither_analysis': slither_result if slither_result else "Slither analysis failed"
                })
            else:
                print(f"Error analyzing contract: {contract_file}")
    
    # Step 4: Generate the report if analysis results exist
    if analysis_results:
        generate_report(analysis_results)
    else:
        print("No analysis results to report. Check the analysis process.")
