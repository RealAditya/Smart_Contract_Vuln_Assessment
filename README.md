# Smart Contract Vulnerability Analysis Tool

A comprehensive security analysis tool for Ethereum smart contracts that uses both Mythril and Slither to detect vulnerabilities and generate detailed reports. Now includes blockchain forensic analysis capabilities!

## Overview

This tool analyzes Solidity smart contracts for security vulnerabilities using two powerful static analysis frameworks:
- **Mythril**: A security analysis tool for EVM bytecode that detects security vulnerabilities using symbolic execution
- **Slither**: A static analysis framework that runs a suite of vulnerability detectors, prints visual information about contract details, and provides an API to easily write custom analyses

The tool generates both individual reports for each contract and a consolidated report with all findings, available in both JSON and HTML formats. It now also includes blockchain forensic analysis capabilities to analyze transaction patterns, trace fund flows, and reconstruct potential attack scenarios.

## Features

- Analyzes multiple smart contracts in a single run
- Detects a wide range of vulnerabilities including:
  - Reentrancy attacks
  - Integer overflow/underflow
  - Unchecked low-level calls
  - Transaction order dependence
  - Unauthorized access
  - and many more
- Generates consolidated reports with vulnerabilities categorized by severity
- Provides detailed HTML report with easy navigation and vulnerability summaries
- Handles complex contract analysis using both Mythril and Slither for comprehensive results

### New Forensic Features

- **Contract History Analysis**: Examines historical transactions for suspicious patterns
- **Funds Flow Tracing**: Visualizes the flow of funds to and from contracts
- **Suspicious Actor Identification**: Identifies addresses with suspicious interaction patterns
- **Attack Reconstruction**: Attempts to reconstruct potential attacks based on vulnerabilities
- **Forensic Reporting**: Generates comprehensive forensic reports with actionable insights

## Installation

### Prerequisites

- Python 3.7 or higher
- Mythril
- Slither
- Solidity compiler (solc)
- Web3.py (for forensic analysis)
- NetworkX and Matplotlib (for visualization)

### Installation Steps

1. **Create a virtual environment** (recommended):
   ```bash
   python -m venv myenv
   source myenv/bin/activate  # On Windows: myenv\Scripts\activate
   ```

2. **Install Mythril**:
   ```bash
   pip install mythril
   ```

3. **Install Slither**:
   ```bash
   pip install slither-analyzer
   ```

4. **Install additional dependencies for forensic analysis**:
   ```bash
   pip install web3 networkx matplotlib pandas
   ```

5. **Install Solidity compiler** (if not already installed):
   Follow instructions at https://docs.soliditylang.org/en/latest/installing-solidity.html

6. **Clone or download this repository**:
   ```bash
   git clone <repository-url>
   cd SmartContract-vulnerability-analysis
   ```

## Usage

### Basic Vulnerability Analysis

1. **Place your smart contracts in the `contracts` directory**:
   - The tool will analyze all `.sol` files in this directory

2. **Run the consolidated report generator**:
   ```bash
   python3 consolidated_report.py
   ```
   
   This will:
   - Automatically run analyzer.py to analyze each contract
   - Generate individual reports for each contract
   - Create a consolidated security report in both JSON and HTML formats

### Forensic Analysis

Run the forensic analysis after vulnerability scanning:

```bash
python3 consolidated_report.py --forensics
```

For more specific forensic analysis, use the dedicated forensic analyzer:

```bash
python3 forensic_analyzer.py --contract 0xYourContractAddress --report consolidated_security_report.json
```

Additional forensic options:
- `--depth`: Specify depth for funds flow analysis (default: 2)
- `--provider`: Specify an Ethereum provider URL
- `--history-only`: Only perform contract history analysis
- `--suspicious-only`: Only perform suspicious actor analysis
- `--flow-only`: Only perform funds flow analysis
- `--attack-only`: Only perform attack reconstruction

## Understanding the Output

The tool generates several types of reports:

### Vulnerability Reports

1. **Individual Contract Reports** (JSON):
   - Located in the `reports` folder
   - Contains both Mythril and Slither analysis results for each contract

2. **Consolidated Security Report** (JSON):
   - Combines all findings in a structured format
   - Includes a vulnerability summary with counts
   - Lists all vulnerabilities by contract

3. **HTML Report**:
   - Provides a user-friendly interface to view all findings
   - Organizes vulnerabilities by contract and tool
   - Color-codes vulnerabilities by severity
   - Includes a table of contents for easy navigation

### Forensic Reports

1. **Contract History Analysis**:
   - Records historical transactions
   - Analyzes transaction patterns and frequencies
   - Identifies anomalies in contract usage

2. **Funds Flow Analysis**:
   - Visual graph of funds movement
   - Identifies key senders and receivers
   - Highlights suspicious fund movements

3. **Suspicious Actor Report**:
   - Lists addresses with unusual interaction patterns
   - Assigns risk scores based on behavior
   - Details specific risk factors for each address

4. **Attack Reconstruction Report**:
   - Links vulnerabilities to potential exploitation
   - Timeline of suspicious transactions
   - Evidence-based attack scenarios

## Troubleshooting

- **Mythril Issues**: If Mythril is failing to analyze contracts, try increasing the execution timeout in analyzer.py
- **Slither Issues**: Ensure you have a compatible version of solc installed for your contracts
- **Web3 Connection**: For forensic analysis, ensure you have access to an Ethereum node or API
- **Missing Reports**: Check for error messages during execution to identify issues

## Project Structure

- `analyzer.py`: Handles individual contract analysis using Mythril and Slither
- `consolidated_report.py`: Main script that runs analyzer.py and generates consolidated reports
- `forensics.py`: Provides blockchain forensic analysis capabilities
- `forensic_analyzer.py`: Command-line tool for standalone forensic analysis
- `contracts/`: Directory for smart contracts to analyze
- `reports/`: Directory where individual reports are stored
- `forensics/`: Directory where forensic reports and visualizations are stored
- `consolidated_security_report.json`: Consolidated findings in JSON format
- `consolidated_security_report.html`: Consolidated findings in HTML format

## License

[Specify your license here]

## Contributors

[Add contributor information if desired]
