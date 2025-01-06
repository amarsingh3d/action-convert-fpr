import zipfile
import xml.etree.ElementTree as ET
import csv
import argparse
from tabulate import tabulate  # Import the tabulate library

# Function to extract audit.xml from .fpr file
def extract_audit_xml(fpr_file):
    with zipfile.ZipFile(fpr_file, 'r') as zip_ref:
        # Check the list of files in the zip to find audit.xml
        if 'audit.xml' in zip_ref.namelist():
            # Read audit.xml as bytes
            with zip_ref.open('audit.xml') as audit_file:
                return audit_file.read()
        else:
            raise ValueError("audit.xml not found in the .fpr file")

# Function to parse the XML and extract relevant information
def parse_audit_xml(xml_data):
    # Parse the XML data
    root = ET.fromstring(xml_data)
    
    # Define the namespaces to search correctly
    namespaces = {
        'ns1': 'xmlns://www.fortify.com/schema/audit'
    }

    # Find the removed issues
    removed_issues = root.findall('.//ns1:RemovedIssue', namespaces)
    
    # List to hold extracted information
    extracted_data = []

    # Iterate through the removed issues and extract the relevant details
    for issue in removed_issues:
        category = issue.find('ns1:Category', namespaces).text
        file = issue.find('ns1:File', namespaces).text
        confidence = issue.find('ns1:Confidence', namespaces).text
        severity = issue.find('ns1:Severity', namespaces).text
        impact = issue.find('ns1:Impact', namespaces).text
        
        # Append the data as a tuple
        extracted_data.append([category, file, confidence, severity, impact])

    return extracted_data

# Function to write data to CSV
def write_to_csv(data, output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        # Write the header
        writer.writerow(['Category', 'File', 'Confidence', 'Severity', 'Impact'])
        # Write the data rows
        writer.writerows(data)

# Function to print data in table format
def print_table(data):
    # Print the table with headers and rows
    headers = ['Category', 'File', 'Confidence', 'Severity', 'Impact']
    print(tabulate(data, headers=headers, tablefmt='grid'))

# Main function to process the .fpr file and create a CSV
def process_fpr_to_csv(fpr_file, output_csv):
    try:
        # Step 1: Extract audit.xml from the .fpr file
        audit_xml_data = extract_audit_xml(fpr_file)
        
        # Step 2: Parse the extracted XML data
        extracted_data = parse_audit_xml(audit_xml_data)
        
        # Step 3: Print the extracted data as a table
        print_table(extracted_data)
        
        # Step 4: Write the extracted data to a CSV file
        write_to_csv(extracted_data, output_csv)
        print(f"Data has been successfully written to {output_csv}")

    except Exception as e:
        print(f"Error: {e}")

# Main function to parse arguments and execute the script
if __name__ == '__main__':
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Extract data from a .fpr file and write to a CSV.")
    parser.add_argument('fpr_file', help="The path to the .fpr file")
    parser.add_argument('output_csv', help="The path to the output CSV file")

    # Parse the arguments
    args = parser.parse_args()

    # Call the function with the provided arguments
    process_fpr_to_csv(args.fpr_file, args.output_csv)
