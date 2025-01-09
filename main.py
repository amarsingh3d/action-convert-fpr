import zipfile
import xml.etree.ElementTree as ET
import pandas as pd
import os
import sys
from tabulate import tabulate

# Function to extract audit details from the given FPR file
def extract_audit_details(fpr_path):
    try:
        # Validate .fpr file extension
        if not fpr_path.endswith('.fpr'):
            print("The provided file is not an FPR file.")
            return

        # Define a fixed output file name
        output_path = "audit_report.txt"

        # Define the path to extract the XML content
        extraction_path = os.getcwd()  # Use current working directory

        # Ensure extraction path exists
        os.makedirs(extraction_path, exist_ok=True)

        # Extract the FPR contents
        with zipfile.ZipFile(fpr_path, 'r') as fpr_zip:
            fpr_zip.extractall(extraction_path)

        # Locate and parse the audit.fvdl file
        fvdl_path = os.path.join(extraction_path, 'audit.fvdl')
        if not os.path.exists(fvdl_path):
            print("audit.fvdl not found in the FPR archive.")
            return

        tree = ET.parse(fvdl_path)
        root = tree.getroot()

        # Namespace handling for FVDL
        namespace = {'fvdl': 'xmlns://www.fortifysoftware.com/schema/fvdl'}

        vulnerabilities = []

        # Extract Vulnerability Details
        for vuln in root.findall('.//fvdl:Vulnerability', namespace):
            kingdom = vuln.findtext('.//fvdl:Kingdom', default='', namespaces=namespace)
            vuln_type = vuln.findtext('.//fvdl:Type', default='', namespaces=namespace)
            severity = vuln.findtext('.//fvdl:DefaultSeverity', default='', namespaces=namespace)
            subtype = vuln.findtext('.//fvdl:Subtype', default='', namespaces=namespace)

            # Extract FunctionDeclarationSourceLocation attributes
            func_decl_elem = vuln.find('.//fvdl:FunctionDeclarationSourceLocation', namespace)
            if func_decl_elem is not None:
                func_decl_path = func_decl_elem.get('path', '')
                func_decl_line = func_decl_elem.get('line', '')
                function_decl_source_loc = f"{func_decl_path} (line {func_decl_line})"
            else:
                function_decl_source_loc = ''

            vulnerabilities.append({
                'Kingdom': kingdom,
                'Type': vuln_type,
                'Subtype': subtype,
                'Severity': severity,
                'SourceLocation': function_decl_source_loc
            })

        # Convert to DataFrame for better display
        df = pd.DataFrame(vulnerabilities)
        if df.empty:
            print("No vulnerabilities found.")
        else:
            print("Extracted Vulnerabilities:")
            print(tabulate(df, headers='keys', tablefmt='grid', showindex=False))

        # Save the vulnerabilities report to the specified output file
        with open(output_path, "w") as f:
            f.write(tabulate(df, headers='keys', tablefmt='grid', showindex=False))

        print(f"Vulnerabilities saved to: {output_path}")

    except Exception as e:
        print(f"An error occurred: {e}")

# Main execution block
if __name__ == "__main__":
    fpr_path = None

    # Check for .fpr files in the current directory
    fpr_files = [file for file in os.listdir(os.getcwd()) if file.endswith('.fpr')]

    if len(fpr_files) == 0:
        print("No .fpr files found in the current directory.")
        sys.exit(1)
    elif len(fpr_files) == 1:
        fpr_path = fpr_files[0]
        print(f"Found .fpr file: {fpr_path}")
    else:
        # Sort files by last modified time, most recent first
        fpr_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        fpr_path = fpr_files[0]
        print(f"Multiple .fpr files found. Picking the most recently updated file: {fpr_path}")

    extract_audit_details(fpr_path)
