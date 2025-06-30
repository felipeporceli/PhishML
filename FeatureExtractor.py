import re
import ssl
import OpenSSL
import datetime
import requests
import socket
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ipaddress

def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return -1  # domínio é um IP -> suspeito/phishing
    except ValueError:
        return 1  # domínio não é IP -> legítimo

def is_long_url(url):
    if len(url) < 54:
        return 1
    elif len(url) <= 75:
        return 0
    else:
        return -1

def is_tiny_url(url):
    tiny_url_pattern = (
        r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|'
        r'tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|'
        r'url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|'
        r'BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|'
        r'fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|'
        r'om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|'
        r'cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|'
        r'buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|'
        r'scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|'
        r'v\.gd|link\.zip\.net'
    )
    return -1 if re.search(tiny_url_pattern, url) else 1

def has_at_symbol(url):
    suspicious_symbols = ['@', '$', '%', '#', '!', '^', '&', '*']
    for symbol in suspicious_symbols:
        if symbol in url:
            return -1 
    return 1 

def has_redirecting_double_slash(url):
    return -1 if url.rfind('//') > 7 else 1

def has_prefix_suffix(domain):
    return -1 if '-' in domain else 1

def count_subdomains(domain):
    subdomain_count = domain.count('.')
    if subdomain_count <= 1:
        return 1      
    elif subdomain_count == 2:
        return 0      
    else:
        return -1    

def get_certificate_info(domain):
    try:
        # Obter o certificado SSL do servidor
        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        
        # Extrair o nome da entidade emissora (issuer)
        issuer_components = dict(x509.get_issuer().get_components())
        issuer_name = issuer_components.get(b'O', b'Unknown').decode('utf-8')
        
        # Datas de validade do certificado
        not_before = x509.get_notBefore().decode('utf-8')
        not_after = x509.get_notAfter().decode('utf-8')
        
        not_before_date = datetime.datetime.strptime(not_before, '%Y%m%d%H%M%SZ')
        not_after_date = datetime.datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
        
        # Calcular idade do certificado em anos
        age = (datetime.datetime.utcnow() - not_before_date).days / 365
        
        # Validar se o certificado está atualmente válido
        now = datetime.datetime.utcnow()
        is_valid = (not_before_date <= now <= not_after_date)
    
        return issuer_name, age, is_valid
    
    except Exception as e:
        return None, None, False

def is_https(url):
    trusted_issuers = [
        "GeoTrust", "GoDaddy", "Network Solutions", "Thawte",
        "Comodo", "Doster", "VeriSign", "Let's Encrypt", "DigiCert",
        "Sectigo", "GlobalSign", "Entrust"
    ]
    minimum_age = 1  # anos

    # Verifica se a URL usa https
    if not url.lower().startswith("https://"):
        return -1  # Phishing

    # Extrai domínio da URL
    try:
        domain = url.split("//")[-1].split("/")[0].lower()
    except Exception:
        return -1  # Phishing por formato inválido

    # Obtém informações do certificado SSL
    issuer, age, valid = get_certificate_info(domain)

    if not valid:
        return -1  # Phishing (certificado inválido)

    # Normaliza o nome do emissor
    issuer_normalized = issuer.strip().lower() if issuer else ""

    # Verifica se emissor está na lista confiável
    trusted_normalized = [x.lower() for x in trusted_issuers]
    if issuer_normalized in trusted_normalized:

        if age is not None and age >= minimum_age:
            return 1 
        else:
            return 0  
    else:
        return 0  

def domain_registration_length(domain):
    try:
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date
        expiration_date = whois_info.expiration_date
    
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if not creation_date or not expiration_date:
            return 0  

        # Calcular o período de registro do domínio
        age = (expiration_date - creation_date).days / 365

        if age >= 1:
            return 1
        else:
            return -1
    except Exception as e:

        return 0

def has_favicon(url, domain):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        icon_links = soup.find_all("link", rel=lambda x: x and ('icon' in x.lower()))
        
        if not icon_links:
            return 0 

        for icon_link in icon_links:
            href = icon_link.get('href')
            if not href:
                continue
            icon_url = urljoin(url, href)
            icon_domain = urlparse(icon_url).netloc.lower()
            domain = domain.lower()

            if icon_domain and icon_domain != domain:
                return -1 

        return 1 

    except Exception:
        return 0 

def is_non_standard_port(url):
    standard_ports = {
        #Portas consideradas comuns
        80,    
        443,   
        21,    
        22,    
        445,   
        1433,  
        1521,  
        3306,  
        3389   
    }
    
    # Portas consideradas suspeitas
    dangerous_ports = {23, 69, 137, 138, 139}
    
    parsed = urlparse(url)
    port = parsed.port

    # Caso não informe porta, atribui padrão com base no esquema
    if port is None:
        if parsed.scheme == 'http':
            port = 80
        elif parsed.scheme == 'https':
            port = 443
    
    if port in dangerous_ports:
        return -1  
    elif port and port not in standard_ports:
        return 0   
    else:
        return 1   

def has_https_token(domain):
    # Verifica se "http" ou "https" aparece no domínio
    domain_lower = domain.lower()
    suspicious_tokens = ['http', 'https']
    
    for token in suspicious_tokens:
        if token in domain_lower:
            return -1  
    
    return 1 

def calculate_request_url(soup, domain):
    try:
        tags = soup.find_all(['img', 'audio', 'embed', 'iframe'])
        total_links = len(tags)
        if total_links == 0:
            return -1

        external_links = 0
        for tag in tags:
            src = tag.get('src')
            if not src:
                continue  
            parsed_url = urlparse(src)
            link_domain = parsed_url.netloc.lower()
            domain_clean = domain.lower().lstrip('www.')
            link_domain_clean = link_domain.lstrip('www.')
            if link_domain_clean != domain_clean and link_domain_clean != '':
                external_links += 1

        percent_external = (external_links / total_links) * 100

        if percent_external < 22:
            return 1    
        elif 22 <= percent_external <= 61:
            return 0    
        else:
            return -1   
    except Exception as e:
        return 0

def calculate_url_of_anchor(soup, domain):
    try:
        anchors = soup.find_all('a')
        total_anchors = len(anchors)
        if total_anchors == 0:
            return -1 

        external_anchors = 0
        for a in anchors:
            href = a.get('href')
            if not href:
                external_anchors += 1  
                continue
            href = href.strip().lower()

            if href in ['#', '', 'javascript:void(0)', 'javascript:void(0);']:
                continue
            if href.startswith('mailto:') or href.startswith('tel:'):
                continue
            
            parsed_href = urlparse(href)
            if parsed_href.netloc and parsed_href.netloc != domain:
                external_anchors += 1

        percent_external = (external_anchors / total_anchors) * 100

        if percent_external < 31:
            return 1   # Legitimo
        elif percent_external <= 67:
            return 0   # Suspeito
        else:
            return -1  # Phishing
    except Exception as e:
        return 1

def calculate_meta_script_link(soup, domain):
    try:
        tags = soup.find_all(['meta', 'script', 'link'])
        if not tags:
            return -1  

        external_tags = 0
        for tag in tags:
            # Alguns desses elementos podem usar 'href' ou 'src'
            url_attr = tag.get('href') or tag.get('src') or ''
            parsed_url = urlparse(url_attr)
            netloc = parsed_url.netloc.lower()
            domain_lower = domain.lower()
            if netloc and netloc != domain_lower:
                external_tags += 1

        percent_external = (external_tags / len(tags)) * 100

        if percent_external < 17:
            return 1  
        elif percent_external <= 81:
            return 0 
        else:
            return -1 
    except Exception as e:
        return 1

def calculate_sfh(soup, domain):
    try:
        forms = soup.find_all('form')
        if not forms:
            return 1
        
        for form in forms:
            action = form.get('action')
            if not action or action.strip() in ["", "about:blank", "javascript:void(0)", "#"]:
                return -1
            
            action_domain = urlparse(action).netloc
            # Se action é relativo (ex: "/submit"), action_domain fica vazio
            if action_domain and action_domain != domain:
                return 0
        return 1
    except Exception:
        return 1

def is_submitting_to_email(soup):
    try:
        forms = soup.find_all('form')
        if not forms:
            return 1 

        for form in forms:
            action = form.get('action', '').lower()
            if action.startswith("mailto:"):
                return -1 

        return 1  
    except Exception:
        return 0  

def extract_hostname_from_whois(url):
    try:
        domain = url.split("//")[-1].split("/")[0].lower()
        
        whois_info = whois.whois(domain)
        
        hostname = whois_info.domain_name
        
        if isinstance(hostname, list):
            hostname = hostname[0]
        
        if hostname:
            hostname = hostname.strip().lower()
        
        return hostname
    
    except Exception as e:
        print(f"Error retrieving WHOIS info for domain '{domain}': {e}")
        return None

def is_abnormal_url(url):
    hostname = extract_hostname_from_whois(url)

    if not hostname:
        return -1

    hostname = hostname.lower()
    domain_in_url = url.split("//")[-1].split("/")[0].lower() if url else ""

    parts = hostname.split('.')
    if len(parts) >= 2:
        main_hostname = '.'.join(parts[-2:])
    else:
        main_hostname = hostname

    if main_hostname and main_hostname in domain_in_url:
        return 1 
    else:
        return -1 

def calculate_website_forwarding(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        redirect_count = len(response.history)
        if redirect_count == 0:
            return 1  
        elif 1 <= redirect_count <= 2:
            return 0  
        elif 3 <= redirect_count <= 4:
            return -1  
        else:
            return -1  
    except requests.exceptions.Timeout:
        return 0  
    except requests.exceptions.RequestException as e:
        print(f"Erro ao verificar redirecionamento: {e}")
        return -1

def is_status_bar_customized(soup):
    try:
        scripts = soup.find_all('script')
        
        for script in scripts:
            if script.string and 'onMouseOver' in script.string:
                return -1 

        for tag in soup.find_all(attrs={"onmouseover": True}):
            return -1
        
        return 1 
    except Exception as e:
        print(f"Error checking status bar customization: {e}")
        return -1 

def is_right_click_disabled(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                content = script.string.lower()
                if ('event.button==2' in content or
                    'event.button === 2' in content or
                    'contextmenu.preventdefault()' in content or
                    'return false;' in content and 'oncontextmenu' in content):
                    return -1  
        
        return 1 
    except Exception as e:
        print(f"Error checking right click disabled: {e}")
        return -1 

def is_using_pop_up_window(soup):
    try:
        scripts = soup.find_all('script')
        for script in scripts:
            content = script.string
            if content and 'window.open' in content:
                inputs = soup.find_all('input', {'type': 'text'})
                if inputs:
                    return -1  

        return 1 
    except Exception as e:
        print(f"Error checking pop-up with text fields: {e}")
        return -1

def has_iframe_redirection(soup):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            if 'frameborder' in iframe.attrs:
                return -1  
        
        return 1 
    except Exception as e:
        print(f"Error checking iframe redirection: {e}")
        return -1  

def calculate_age_of_domain(domain):
    try:
        whois_info = whois.whois(domain)
        age = (whois_info.expiration_date - whois_info.creation_date).days / 30
        return -1 if age >= 6 else 1
    except:
        return 1

def has_dns_record(domain):
    try:
        whois_info = whois.whois(domain)
        return 1 if whois_info else -1
    except:
        return 1

def calculate_website_traffic(domain):
    try:
        url = f"http://data.alexa.com/data?cli=10&dat=s&url={domain}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        alexa_data = response.text
        match = re.search(r'<POPULARITY URL=".*?" TEXT="(\d+)" SOURCE="panel">', alexa_data)
        
        if match:
            rank = int(match.group(1))
            if rank < 100000:
                return 1 
            else:
                return 0  
        else:
            return -1
    except requests.RequestException as e:
        print(f"Request error while fetching Alexa data: {e}")
        return -1
    except Exception as e:
        print(f"Unexpected error in calculate_website_traffic: {e}")
        return -1

def calculate_page_rank(domain):
    try:
        # Placeholder para obter o PageRank
        pagerank = get_pagerank(domain) 
        
        if pagerank is None:
            return -1 
        if not isinstance(pagerank, (int, float)) or pagerank < 0:
            return -1
        
        return 1 if pagerank >= 0.2 else -1
    except Exception as e:
        print(f"Erro ao calcular PageRank: {e}")
        return -1

def is_google_indexed(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
                      " Chrome/115.0 Safari/537.36"
    }
    try:
        response = requests.get(f"https://www.google.com/search?q=site:{url}", headers=headers, timeout=5)
        response.raise_for_status()
        page_text = response.text.lower().replace(" ", "")
        if "didnotmatchanydocuments" in page_text:
            return -1
        else:
            return 1
    except requests.RequestException:
        return -1

def is_link_pointing_to_page(domain):
    try:
        alexa_rank = requests.get(f"http://data.alexa.com/data?cli=10&dat=s&url={domain}").text
        rank = re.search(r'<LINKSIN NUM="(\d+)"/>', alexa_rank)
        if rank:
            if int(rank.group(1)) == 0:
                return -1 
            elif int(rank.group(1)) <= 2:
                return 0 
            else:
                return 1 
        else:
            return -1
    except:
        return -1

def check_phishtank(url):
    try:
        phishtank_url = "https://data.phishtank.com/data/online-valid.json"
        response = requests.get(phishtank_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                if 'url' in entry and entry['url'].lower() == url.lower():
                    return True
        return False
    except Exception as e:
        print(f"Erro ao consultar PhishTank: {e}")
        return False

def calculate_statistical_report_online(url):
    if check_phishtank(url):
        return -1  
    else:
        return 1 

def extract_features(url):
    domain = urlparse(url).netloc
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    features = {
        'UsingIP': [is_ip_address(domain)],
        'LongURL': [is_long_url(url)],
        'ShortURL': [is_tiny_url(url)],
        'PrefixSuffix-': [has_prefix_suffix(domain)],
        'SubDomains': [count_subdomains(domain)],
        'HTTPS': [is_https(url)],
        'DomainRegLen': [domain_registration_length(domain)],
        'RequestURL': [calculate_request_url(soup, domain)],
        'AnchorURL': [calculate_url_of_anchor(soup, domain)],
        'LinksInScriptTags': [calculate_meta_script_link(soup, domain)],
        'ServerFormHandler': [calculate_sfh(soup, domain)],
        'AbnormalURL': [is_abnormal_url(domain)],
        'AgeofDomain': [calculate_age_of_domain(domain)],
        'DNSRecording': [has_dns_record(domain)],
        'WebsiteTraffic': [calculate_website_traffic(domain)],
        'PageRank': [calculate_page_rank(domain)],
        'GoogleIndex': [is_google_indexed(url)],
        'StatsReport': [calculate_statistical_report_online(url)]
    }
    for x in features.values():
        if(x[0]==None):
            x[0]=1
    return features