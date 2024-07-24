# Enumerate Azure WebApp URLs using Python Requests and Beautiful Soup

import requests
from bs4 import BeautifulSoup
import re

# URL to fetch
URL = "https://crt.sh/?Identity=azurewebsites.net&exclude=expired"

# Local file to save the initial output
output_file = "temp_urls.txt"

# Fetch the webpage content
response = requests.get(URL)
response.raise_for_status()

# Parse the HTML content using BeautifulSoup
soup = BeautifulSoup(response.text, 'html.parser')

# Extract URLs from the table
urls = set()
for td in soup.find_all('td'):
    # Use regex to find all .azurewebsites.net occurrences
    matches = re.findall(r'[\w.-]+\.azurewebsites\.net', td.get_text())
    for match in matches:
        urls.add(match)

# Save the unique URLs to a file
with open(output_file, 'w') as file:
    for url in sorted(urls):
        file.write(url + '\n')

# Process the file to place any text after .azurewebsites.net on a new line and keep only unique values
processed_urls = set()
with open(output_file, 'r') as file:
    for line in file:
        line = line.strip()
        # Split by .azurewebsites.net and re-join with newline if needed
        split_parts = re.split(r'(?<=\.azurewebsites\.net)', line)
        for part in split_parts:
            if part:  # Avoid adding empty strings
                processed_urls.add(part.strip())

# Filter out URLs containing "scm", remove leading dots, and save the processed unique URLs back to the file
with open(output_file, 'w') as file:
    for url in sorted(processed_urls):
        clean_url = url.lstrip('.')  # Remove leading dot if present
        if "scm" not in clean_url:
            file.write(clean_url + '\n')

print(f"Processed unique URLs saved to {output_file}")
