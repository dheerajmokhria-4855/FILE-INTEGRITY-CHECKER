from bs4 import BeautifulSoup
import urllib.parse as urlparse
from collections import deque

class Scanner:
    """
    A class to represent a web vulnerability scanner.
    It crawls a website and checks for common vulnerabilities like
    Cross-Site Scripting (XSS) and SQL Injection (SQLi).
    """

    def __init__(self, base_url):
        """
        Initializes the Scanner.

        Args:
            base_url (str): The starting URL of the website to scan.
        """
        if not base_url.startswith('http'):
            print("[-] Error: Please provide a full URL (e.g., http://example.com)")
            exit()

        self.base_url = base_url
        self.target_domain = urlparse.urlparse(base_url).netloc
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})

        self.links_to_scan = set([self.base_url])
        self.scanned_links = set()
        self.vulnerabilities_found = []

    def crawl(self):
        """
        Crawls the website to discover all unique links and forms
        within the same domain.
        """
        print("[*] Starting crawl from:", self.base_url)
        queue = deque([self.base_url])
        discovered_links = set([self.base_url])

        while queue:
            current_url = queue.popleft()
            if current_url in self.scanned_links:
                continue

            print(f"[~] Crawling: {current_url}")
            self.scanned_links.add(current_url)

            try:
                response = self.session.get(current_url, timeout=5)
                soup = BeautifulSoup(response.content, 'html.parser')

                
                for a_tag in soup.find_all('a', href=True):
                    link = urlparse.urljoin(self.base_url, a_tag['href'])
                    
                    if self.target_domain in urlparse.urlparse(link).netloc and link not in discovered_links:
                        discovered_links.add(link)
                        queue.append(link)
                        self.links_to_scan.add(link)

            except requests.RequestException as e:
                print(f"[-] Could not connect to {current_url}. Error: {e}")

        print(f"[+] Crawl finished. Found {len(self.links_to_scan)} unique links to scan.")


    def scan_for_xss(self, url):
        """
        Scans a given URL for Cross-Site Scripting (XSS) vulnerabilities
        by testing forms and URL parameters.
        """
        print(f"\n[*] Scanning for XSS on: {url}")
        xss_payloads = [
            "<script>alert('xss')</script>",
            "'><script>alert('xss')</script>",
            "\"<script>alert('xss')</script>"
        ]

        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all("form")

            
            for form in forms:
                action = form.get("action")
                post_url = urlparse.urljoin(url, action)
                method = form.get("method", "get").lower()

                for payload in xss_payloads:
                    inputs_data = {}
                    for input_tag in form.find_all("input"):
                        input_name = input_tag.get("name")
                        input_type = input_tag.get("type", "text")
                        if input_type == "text" and input_name:
                            inputs_data[input_name] = payload

                    if method == "post":
                        res = self.session.post(post_url, data=inputs_data, timeout=5)
                    else:
                        res = self.session.get(post_url, params=inputs_data, timeout=5)

                    if payload in res.text:
                        vulnerability = {
                            "type": "XSS",
                            "url": res.url,
                            "payload": payload,
                            "element": f"Form on {url}"
                        }
                        print(f"[!] XSS Vulnerability Found!")
                        print(f"    URL: {res.url}")
                        print(f"    Payload: {payload}")
                        self.vulnerabilities_found.append(vulnerability)

        except requests.RequestException as e:
            print(f"[-] Error during XSS scan on {url}: {e}")


    def scan_for_sqli(self, url):
        """
        Scans a given URL for basic error-based SQL Injection vulnerabilities.
        """
        print(f"[*] Scanning for SQLi on: {url}")
        sqli_payload = "'"  
        sql_error_messages = {
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "supplied argument is not a valid mysql result resource"
        }

        try:
            
            parsed_url = urlparse.urlparse(url)
            query_params = urlparse.parse_qs(parsed_url.query)

            for param in query_params:
                original_value = query_params[param][0]
                query_params[param] = original_value + sqli_payload
                
                modified_query = urlparse.urlencode(query_params, doseq=True)
                test_url = parsed_url._replace(query=modified_query).geturl()

                res = self.session.get(test_url, timeout=5)
                for error in sql_error_messages:
                    if error in res.text.lower():
                        vulnerability = {
                            "type": "SQL Injection",
                            "url": test_url,
                            "payload": sqli_payload,
                            "parameter": param
                        }
                        print(f"[!] SQL Injection Vulnerability Found!")
                        print(f"    URL: {test_url}")
                        print(f"    Parameter: {param}")
                        self.vulnerabilities_found.append(vulnerability)
                        break 

        except requests.RequestException as e:
            print(f"[-] Error during SQLi scan on {url}: {e}")

    def run_scanner(self):
        """
        Runs the full scan: crawl, then scan each link for vulnerabilities.
        """
        self.crawl()
        for link in list(self.links_to_scan):
            self.scan_for_xss(link)
            self.scan_for_sqli(link)

        print("\n" + "="*50)
        print("[*] Scan Complete.")
        if self.vulnerabilities_found:
            print(f"[!] Found {len(self.vulnerabilities_found)} vulnerabilities.")
            for vuln in self.vulnerabilities_found:
                print(f"    - Type: {vuln['type']}, URL: {vuln['url']}")
        else:
            print("[+] No common XSS or SQLi vulnerabilities found.")
        print("="*50)


if __name__ == "__main__":

    target_website = "http://testphp.vulnweb.com/" 

    scanner = Scanner(target_website)
    scanner.run_scanner()

