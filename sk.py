import requests
from bs4 import BeautifulSoup
import re

# XXE açığı tespiti
def detect_xxe(xml_string):
    xxe_patterns = [
        r'<!ENTITY\s+%s\s+"[^"]*">' % entity_name
        for entity_name in ['file', 'uri', 'tricky']
    ]
    
    for pattern in xxe_patterns:
        if re.search(pattern, xml_string):
            return True  # XXE açığı algılandı
    
    return False  # XXE açığı bulunamadı

# SQL açığı tespiti
def detect_sql_injection(input_string):
    sql_injection_patterns = [
        r'\bUNION\s+SELECT\b',
        r'\bSELECT\b.*\bFROM\b',
        r'\bINSERT\b.*\bINTO\b',
        r'\bUPDATE\b.*\bSET\b',
        r'\bDELETE\b.*\bFROM\b',
    ]
    
    for pattern in sql_injection_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True  # SQL açığı algılandı
    
    return False  # SQL açığı bulunamadı

# XSS açığı tespiti
def detect_xss(input_string):
    xss_patterns = [
        r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',
        r'on\w+="[^"]+"',
        r'javascript:',
        r'\balert\b',
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True  # XSS açığı algılandı
    
    return False  # XSS açığı bulunamadı

# OS komutu enjeksiyonu açığı tespiti
def detect_os_command_injection(input_string):
    os_command_patterns = [
        r';\s*system\s*\(',
        r';\s*exec\s*\(',
        r';\s*popen\s*\(',
    ]
    
    for pattern in os_command_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True  # OS komutu enjeksiyonu açığı algılandı
    
    return False  # OS komutu enjeksiyonu açığı bulunamadı

# Web sitesinden tüm linkleri alır
def get_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    links = []
    
    for link in soup.find_all('a'):
        href = link.get('href')
        if href:
            links.append(href)
    
    return links

# Kullanıcıdan web sitesi URL'si al
url = input("Web sitesi URL'si: ")

# Tüm linkleri al
links = get_links(url)

# Her bir link için güvenlik açıklarını tara
for link in links:
