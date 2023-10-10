import urllib.parse
import json
import csv
import os
import re
import sys
import os
from bs4 import BeautifulSoup
import requests
import re
import validators
from urllib.parse import urlparse, urljoin
import urllib.parse
import whois21
import time
from datetime import datetime
from urllib.parse import urlencode
from selenium import webdriver
import signal



def parse_url(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.scheme + "://" + parsed_url.netloc
    domain = parsed_url.netloc
    return hostname, domain, parsed_url.path

# RETURN CODES
# 0 stands for legitimate
# 1 stands for phishing

def get_url_length(url):
	return len(url)


def get_hostname_length(url):
	hostname, domain, path = parse_url(url)
	return len(hostname)


def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '[0-9a-fA-F]{7}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0


def count_hyphens(base_url):
    return base_url.count('-')


def count_and(base_url):
    return base_url.count('&')


def count_eq(base_url):
    return base_url.count('=')


def count_underscore(base_url):
    return base_url.count('_')


def count_slash(base_url):
    return base_url.count('/')


def https_token(url):
    if url[0:5] == 'https':
        return 0
    return 1


def port(url):
    if re.search("^[a-z][a-z0-9+\-.]*://([a-z0-9\-._~%!$&'()*+,;=]+@)?([a-z0-9\-._~%]+|\[[a-z0-9\-._~%!$&'()*+,;=:]+\]):([0-9]+)",url):
        return 1
    return 0


def get_number_of_hyperlinks(soup, url):

    hyperlinks = {'internal':0, 'external':0, 'null':0, 'total':0}

    base_url = urlparse(url).netloc

    for el in soup.find_all(href=True):

        if el['href'] in Null_format:
            hyperlinks['null']+=1
        else:
            full_url = urljoin(url, el.get('href'))
            parsed_url = urlparse(full_url)

            if parsed_url.netloc == base_url:
                hyperlinks['internal']+=1
            else:
                hyperlinks['external']+=1
        
        hyperlinks['total']+=1
    
    return hyperlinks


def get_null_hyperlinks_ratio(soup, domain):
    hyperlinks = get_number_of_hyperlinks(soup, domain)
    if hyperlinks['total']:
        return round(hyperlinks['null'] / hyperlinks['total'], 2)
    return None


def get_internal_hyperlinks_ratio(soup, domain):
    hyperlinks = get_number_of_hyperlinks(soup, domain)
    if hyperlinks['total']:
        return round(hyperlinks['internal'] / hyperlinks['total'], 2)
    return None

def get_external_hyperlinks_ratio(soup, domain):
    hyperlinks = get_number_of_hyperlinks(soup, domain)
    if hyperlinks['total']:
        return round(hyperlinks['external'] / hyperlinks['total'], 2)
    return None

def get_forms(soup, hostname, domain):
    Forms = {'internals': [], 'null': [], 'externals': []}
    # collect all forms 
    for form in soup.find_all('form'):
        action = form.get('action')
        if action:
            if action.strip() in Null_format:
                Forms['null'].append(form)
            elif action.startswith('/'):
                Forms['internals'].append(form)   
            else:
                Forms['externals'].append(form)
        else:
            Forms['null'].append(form)
    return Forms


def login_form(Forms):
    p = re.compile('([a-zA-Z0-9\_])+.php')
    if len(Forms['externals'])>0:
        return 'external login forms found'
    elif len(Forms['null'])>0:
        return 'null login forms found'
    for form in Forms['internals']+Forms['externals']:
        if p.match(str(form)) != None :
            return [form, "-s action is suspicious"]
    return None


def favicon_external_source(soup):
    try:
        favicon_link = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        
        if favicon_link:
            favicon_url = favicon_link.get('href')
            parsed_url = urlparse(favicon_url)
            
            if parsed_url.netloc != '':
                # print("Favicon is loaded from an external source:", favicon_url)
                return favicon_url
            else:
                # print("Favicon is loaded from the same domain as the website.")
                return False
        else:
            # print("No favicon found on the website.")
            return None
    
    except requests.exceptions.RequestException as e:
        # print("An error occurred:", e)
        return None


def get_title(soup):
    return soup.title.string


def domain_in_title(domain, soup):
    # print("domain", domain.lower())
    # print("soup.title.string.lower()", soup.title.string.lower())
    if domain.lower() in get_title(soup).lower(): 
        return 1
    return None


def submitting_to_email(Form):
    for form in Form['internals'] + Form['externals']:
        if "mailto:" in form or "mail()" in form:
            return 1
        else:
            return None
    return None




def has_popup_window(url):
    try:
        # Initialize a Selenium webdriver 
        driver = webdriver.Chrome() 

        # Open the website
        driver.get(url)

        # Check if there are any open pop-up windows
        popup_handles = driver.window_handles
        if len(popup_handles) > 1:
            return(popup_handles)
        else:
            return(0)

        # Close the browser
        driver.quit()

    except Exception as e:
        return "An error occurred:", e




# ------------------------------- domain ---------

def whois_registered(domain):
    try:
        res = whois21.WHOIS(domain)
        return res
    except:
        return None


def domain_registration_length(domain):
    try:
        res = whois_registered(domain)
        # print("whois request:", res)
        expiration_date = res.expires_date
        # print("expiration_date: {}".format(expiration_date))
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            return 0
    except:
        return None


def google_index(url):
    #time.sleep(.6)
    user_agent =  'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
    headers = {'User-Agent' : user_agent}
    query = {'q': 'site:' + url}
    google = "https://www.google.com/search?" + urlencode(query)
    data = requests.get(google, headers=headers)
    data.encoding = 'ISO-8859-1'
    soup = BeautifulSoup(str(data.content), "html.parser")
    try:
        if 'Our systems have detected unusual traffic from your computer network.' in str(soup):
            return -1
        check = soup.find(id="rso").find("div").find("div").find("a")
        #print(check)
        if check and check['href']:
            return 0
        else:
            return 1
        
    except AttributeError:
        return 1







def result(url):
	content = getPageContent(url)
	if content != None:
		soup = BeautifulSoup(content, 'html.parser')
		hostname, domain, path = parse_url(url)
	print('\nlength URL:', get_url_length(url))
	print('\nlength hostname:', get_hostname_length(url))
	print('\nIP:', having_ip_address(url))
	print('\nnb of hyphens:', count_hyphens(url))
	print('\nnb of and:', count_and(url))
	print('\nnb of eq:', count_eq(url))
	print('\nnb of underscore:', count_underscore(url))
	print('\nnb of slash:', count_slash(url))
	print('\nhttps token:', https_token(url))
	print('\nport:', port(url))
	print('\nbrand: CHECK')
	print('\nnb of hyperlinks:', get_number_of_hyperlinks(soup, url)['total'])
	print('\nratio of internal hyperlinks:', get_internal_hyperlinks_ratio(soup, domain))
	print('\nratio of external hyperlinks:', get_external_hyperlinks_ratio(soup, domain))
	print('\nratio of null hyperlinks:', get_null_hyperlinks_ratio(soup, domain))
	print('\nlogin form:', login_form(get_forms(soup, hostname, domain)))
	print('\nexternal favicon:', favicon_external_source(soup))
	print('\nsubmitting to email:', submitting_to_email(get_forms(soup, hostname, domain)))
	print('\niframe:', 1 if soup.findAll('iframe') else 0)
	print('\npop up:', has_popup_window(url))
	print('\ndomain_in_title:', domain_in_title(domain, soup))
	print('\nwhois_registered:', whois_registered(domain))
	print('\ndomain_registration_length:', domain_registration_length(domain))
	print('\ngoogle_index:', google_index(url))
	print('-------------------------------------------\n')


while True:
	url = input("Please enter url: ")
	result(url)




