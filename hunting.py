import requests
import re
import json
import pandas as pd

# Prompt user for the VirusTotal and Triage API keys securely
VIRUSTOTAL_API_KEY = ''
TRIAGE_API_KEY=""
YOUTRACK_API_KEY=""

# Example indicators including IP addresses and SHA-256 hashes
indicators = ["8.8.8.8", "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c", "orange.com", "b70e59a589cca565eb07ae8489590f19bf28a6176e38c2d117d41ed4d58578cb"]  # Replace with actual values

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.ip_base_url = 'https://www.virustotal.com/api/v3/ip_addresses/'
        self.hash_base_url = 'https://www.virustotal.com/api/v3/files/'
        self.domain_base_url = 'https://www.virustotal.com/api/v3/domains/'

    def is_ip(self, indicator):
        """
        Check if the indicator is an IP address.
        """
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        return bool(ip_pattern.match(indicator))

    def is_hash(self, indicator):
        """
        Check if the indicator is a SHA-256 hash.
        """
        hash_pattern = re.compile(r'^[a-fA-F0-9]{64}$')
        return bool(hash_pattern.match(indicator))

    def is_domain(self, indicator):
        """
        Check if the indicator is a domain name.
        """
        domain_pattern = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
        return bool(domain_pattern.match(indicator))

    def fetch_results(self, indicators):
        """
        Fetches results from the VirusTotal API for the given list of indicators.
        """
        results = []
        
        for indicator in indicators:
            if self.is_ip(indicator):
                base_url = self.ip_base_url
                indicator_type = 'ip-address'
            elif self.is_hash(indicator):
                base_url = self.hash_base_url
                indicator_type = 'file'
            elif self.is_domain(indicator):
                base_url = self.domain_base_url
                indicator_type = 'domain'
            else:
                continue  # Skip invalid indicators
                
            url = f'{base_url}{indicator}'
            headers = {'x-apikey': self.api_key}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                json_response = response.json()
                score = json_response.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                results.append({
                    'indicator': indicator,
                    'indicator_type': indicator_type,
                    'vt_score': score,
                    'vt_link': f'https://www.virustotal.com/gui/{indicator_type.lower()}/{indicator}'
                })
            else:
                results.append({
                    'indicator': indicator,
                    'indicator_type': indicator_type,
                    'vt_score': 'N/A',
                    'vt_link': 'N/A'
                })
        
        return results

    def fetch_malwarebazaar_info(self, hash_value):
        """
        Fetches information from the MalwareBazaar API for the given hash.
        """
        url = 'https://mb-api.abuse.ch/api/v1/'
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'query': 'get_info',
            'hash': hash_value
        }
        
        response = requests.post(url, headers=headers, data=data)
        
        if response.status_code == 200:
            json_response = response.json()
            if json_response['query_status'] == 'ok':
                return json_response['data']
            else:
                return {'error': json_response['query_status']}
        else:
            return {'error': 'Request failed with status code {}'.format(response.status_code)}

    def generate_report(self, results):
        """
        Generates a threat hunting report from the results.
        """
        report = "Threat Hunting Report\n"
        report += "="*20 + "\n\n"
        for result in results:
            report += f"- Indicator: {result['indicator']}\n"
            report += f"Type: {result['indicator_type']}\n"
            report += f"VirusTotal Score: {result['vt_score']}\n"
            report += f"VirusTotal Link: {result['vt_link']}\n"
            if result['indicator_type'] == 'file':
                malware_info = self.fetch_malwarebazaar_info(result['indicator'])
                if 'error' in malware_info:
                    report += f"MalwareBazaar Info: Error: {malware_info['error']}\n"
                else:
                    for entry in malware_info:
                        report += f"MalwareBazaar: \n"
                        report += f"SHA256 Hash: {entry.get('sha256_hash', 'N/A')}\n"
                        report += f"First Seen: {entry.get('first_seen', 'N/A')}\n"
                        report += f"Last Seen: {entry.get('last_seen', 'N/A')}\n"
                        report += f"File Name: {entry.get('file_name', 'N/A')}\n"
                        report += f"File Type: {entry.get('file_type', 'N/A')}\n"
                        report += f"File Size: {entry.get('file_size', 'N/A')} bytes\n"
                        report += f"Tags: {', '.join(entry.get('tags', []))}\n"
                        report += f"Signature: {entry.get('signature', 'N/A')}\n"
                        report += f"Download URL: {entry.get('urlhaus_download', 'N/A')}\n"
                        triage_info = entry.get('vendor_intel', {}).get('Triage', {})
                        report += f"Triage: {triage_info}\n"
                        if triage_info and 'link' in triage_info:
                            triage_id = self.extract_triage_id(triage_info['link'])
                            if triage_id:
                                triage_report = triage.get_triage_report(triage_id)
                                #print(triage_report)
                                if 'targets' in triage_report:
                                    report += self.format_triage_report(triage_report)
                        report += "-"*20 + "\n"
            report += "="*20 + "\n"
        
        return report

    def extract_triage_id(self, link):
        """
        Extracts the ID from a Triage link.
        """
        match = re.search(r'reports/(\d{6}-[a-z0-9]{10})', link)
        return match.group(1) if match else None

    def format_triage_report(self, report_data):
        """
        Formats the Triage report data for inclusion in the final report.
        """
        formatted_report = "\nTriage Report\n"
        formatted_report += "-"*20 + "\n"
        if 'targets' not in report_data or not report_data['targets']:
            formatted_report += "No target information available.\n"
            return formatted_report
        
        iocs_data = report_data['targets'][0].get('iocs', {})
        
        formatted_report += "Domains:\n"
        for domain in iocs_data.get('domains', []):
            formatted_report += f"- {domain}\n"
        
        formatted_report += "IPs:\n"
        for ip in iocs_data.get('ips', []):
            formatted_report += f"- {ip}\n"
        
        formatted_report += "URLs:\n"
        for url in iocs_data.get('urls', []):
            formatted_report += f"- {url} (Port: {self.extract_port(url)})\n"
        
        return formatted_report

    def extract_port(self, url):
        """
        Extracts the port from a URL if present.
        """
        match = re.search(r':(\d+)', url)
        return match.group(1) if match else 'N/A'

class Triage():
    def __init__(self, api_key):
        self.base_url = "https://tria.ge/api/v0/samples"
        self.api = {'Authorization': 'Bearer ' + api_key}
        
    def get_triage_report(self, id):
        url = f'{self.base_url}/{id}/overview.json'
        response = requests.get(url, headers=self.api)
        return response.json()

def generate_xql_query(domains, ips, start_time, end_time, agent_hostname):
    domain_filters = ' or '.join([f'dns_query_name = "*{domain}*"' for domain in domains])
    
    filters = ' or '.join(filter(None, [domain_filters]))
    
    xql_query = f"""
    config timeframe between "{start_time}" and "{end_time}"
    | preset = network_story 
    | filter agent_hostname = "{agent_hostname}" and (dns_query_name != null and ({filters}))
    | dedup dns_query_name
    | fields _time, dns_query_name 
    | sort asc _time
    """
    return xql_query

# Initialize the Triage and VirusTotalAPI with the provided API keys
triage = Triage(TRIAGE_API_KEY)
vt_api = VirusTotalAPI(VIRUSTOTAL_API_KEY)

# Fetch results for mixed indicators
virustotal_results = vt_api.fetch_results(indicators)

# Generate the report
report = vt_api.generate_report(virustotal_results)

# Extract values from MalwareBazaar and Triage reports for XQL query
domains_list = []
ips_list = []
for result in virustotal_results:
    if result['indicator_type'] == 'file':
        malware_info = vt_api.fetch_malwarebazaar_info(result['indicator'])
        #print(malware_info)
        #False code
        if 'error' not in malware_info:
            for entry in malware_info:
                triage_info = entry.get('vendor_intel', {}).get('Triage', {})
                print(triage_info)
                if triage_info and 'link' in triage_info:
                    triage_id = vt_api.extract_triage_id(triage_info['link'])
                    if triage_id:
                            triage_report = triage.get_triage_report(triage_id)
                            if 'targets' in triage_report and triage_report['targets']:
                                    iocs_data = triage_report['targets'][0].get('iocs', {})
                                    domains_list.extend(iocs_data.get('domains', []))
                                    ips_list.extend(iocs_data.get('ips', []))


"""                
                domains_list.extend(entry.get('tags', []))  # Assuming 'tags' might contain domains
                c2_list = entry.get('vendor_intel', {}).get('Triage', {}).get('malware_config', [])
                print(c2_list)
                for c2 in c2_list:
                    if 'c2' in c2:
                        c2_domain = c2['c2'].split(':')[0]
                        if re.match(r'^[a-zA-Z0-9.-]+$', c2_domain):  # simple domain validation
                            domains_list.append(c2_domain)
        triage_info = result.get('triage_info', {})
        print(triage_info)
        if triage_info:
            triage_id = vt_api.extract_triage_id(triage_info.get('link', ''))
            print(triage_id)
            if triage_id:
                triage_report = triage.get_triage_report(triage_id)
                if 'targets' in triage_report and triage_report['targets']:
                    iocs_data = triage_report['targets'][0].get('iocs', {})
                    domains_list.extend(iocs_data.get('domains', []))
                    ips_list.extend(iocs_data.get('ips', []))
"""                    
# Timeframe and hostname for XQL query
start_time = "2024-04-02 09:35:00 +0200"
end_time = "2024-04-02 09:42:00 +0200"
agent_hostname = "C06534342"

# Generate XQL query
xql_query = generate_xql_query(domains_list, ips_list, start_time, end_time, agent_hostname)

#print(report)
print(xql_query)


def send_comment(data):
    url = "http://scootylabs.com/api/articles/145-28/comments?fields=id,author(id,name),text,created,visibility(permittedGroups(id,name),permittedUsers(id,name))"
    headers = {
        'Authorization': f'Bearer {YOUTRACK_API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = json.dumps({
            "text": data
        })
    response = requests.request("POST", url, headers=headers, data=payload)
    return response


send_comment(report)
send_comment(xql_query)

