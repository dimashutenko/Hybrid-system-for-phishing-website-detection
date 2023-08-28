import urllib.parse
import tldextract
import requests
import json
import csv
import os
import re
import sys
import os
from flask import Flask, render_template, request
from bs4 import BeautifulSoup
import requests
import re
import tldextract
import validators
import urllib.parse
from urllib.parse import urlparse
import whois21
import time
from datetime import datetime
from urllib.parse import urlencode


import signal

# source https://data.mendeley.com/datasets/c2gw7fy2j4/3/files/01f5fa84-8d41-4692-9878-983f615ff1d7

Null_format = ["", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whatever",
               "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript", "about:blank"]

def is_URL_accessible(url):
    iurl = url
    parsed = urlparse(url)
    url = parsed.scheme+'://'+parsed.netloc
    page = None
    try:
        page = requests.get(url, timeout=5)   
    except:
        parsed = urlparse(url)
        url = parsed.scheme+'://'+parsed.netloc
        if not parsed.netloc.startswith('www'):
            url = parsed.scheme+'://www.'+parsed.netloc
            try:
                page = requests.get(url, timeout=5)
            except:
                page = None
                pass
        if not parsed.netloc.startswith('www'):
            url = parsed.scheme+'://www.'+parsed.netloc
            iurl = iurl.replace('https://', 'https://www.')
            try:
                page = requests.get(url)
            except:        
                url = 'http://'+parsed.netloc
                iurl = iurl.replace('https://', 'http://')
                try:
                    page = requests.get(url) 
                except:
                    if not parsed.netloc.startswith('www'):
                        url = parsed.scheme+'://www.'+parsed.netloc
                        iurl = iurl.replace('http://', 'http://www.')
                        try:
                            page = requests.get(url)
                        except:
                            pass
                pass 
    if page and page.status_code == 200 and page.content not in ["b''", "b' '"]:
        return True, url, page
    else:
        return False, None, None


def get_domain_1(url):
    o = urllib.parse.urlsplit(url)
    return o.hostname, tldextract.extract(url).domain, o.path


def parse_url(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.scheme + "://" + parsed_url.netloc
    domain = parsed_url.netloc
    return hostname, domain, parsed_url.path



def getPageContent_original(url):
    parsed = urlparse(url)
    url = parsed.scheme+'://'+parsed.netloc
    try:
        page = requests.get(url)
    except:
        if not parsed.netloc.startswith('www'):
            url = parsed.scheme+'://www.'+parsed.netloc
            page = requests.get(url)
    if page.status_code != 200:
        return None
    else:    
        return page.content


def getPageContent(url):
    return urllib.request.urlopen(url).read().decode('utf-8')




# ------------------------------- DOM ---------


def number_of_hyperlinks(soup):
    return len(soup.find_all(href=True)) 


def get_number_of_hyperlinks(soup, domain):
    hyperlinks = {'internal':0, 'external':0, 'null':0, 'uncategorized':0, 'total':0}
    for el in soup.find_all(href=True):
        if el['href'] in Null_format:
            hyperlinks['null']+=1
        elif domain in el['href']:
            hyperlinks['internal']+=1
        elif domain not in el['href']:
            hyperlinks['external']+=1
        else:
            hyperlinks['uncategorized']+=1
        hyperlinks['total']+=1
    return hyperlinks


def get_null_hyperlinks_ratio(soup, domain):
    if get_number_of_hyperlinks(soup, domain)['total']:
        return round(get_number_of_hyperlinks(soup, domain)['null'] / get_number_of_hyperlinks(soup, domain)['total'], 2)
    else:
        return None


def get_internal_hyperlinks_ratio(soup, domain):
    if get_number_of_hyperlinks(soup, domain)['total']:
        return round(get_number_of_hyperlinks(soup, domain)['internal'] / get_number_of_hyperlinks(soup, domain)['total'], 2)
    else:
        return None

def get_external_hyperlinks_ratio(soup, domain):
    if get_number_of_hyperlinks(soup, domain)['total']:
        return round(get_number_of_hyperlinks(soup, domain)['external'] / get_number_of_hyperlinks(soup, domain)['total'], 2)
    else:
        return None


def check_identity(url, soup):
    extracted = tldextract.extract(url)
    domain = str(extracted.domain) + "." + str(extracted.suffix)
    # print("\n domain: " + domain + "\n")  
    a_tags = soup.find_all("a")
    a_tags_refferencing_outside = 0
    for a_tag in a_tags:
        if str(domain) not in str(a_tag) and a_tag.get("href")[0] != '/' and a_tag.get("href")[0] != '#':
            a_tags_refferencing_outside+=1
        # else:
            # print(str(domain) + " is in " + str(a_tag))
    # print("\n Number of <a> tags refferencing outside:", a_tags_refferencing_outside)
    if a_tags_refferencing_outside > len(a_tags)/2:
        # print(" more than half of <a> tags point to other domains, PHISHING SUSPECTED")
        return False
    else:
        # print(str(a_tags_refferencing_outside) + " out of " + str(len(a_tags)) + " <a> tags point to other domains \n")
        return True


def get_inputs(soup):
    #print(soup)
    inputs = soup.findAll("input", {"name" : re.compile("name", re.IGNORECASE)})  # finds all the input tags that have attribute "name" and contain value "name"
    inputs.append( soup.find_all("input", attrs={"name": "username"}) )
    inputs.append( soup.find_all("input", attrs={"name": re.compile("mail")}) )
    inputs.append( soup.find_all("input", attrs={"name": re.compile("login")}) )
    inputs.append( soup.find_all("input", attrs={"name": re.compile("id")}) )
    inputs.append( soup.find_all("input", attrs={"name": re.compile("phone")}) )
    inputs.append( soup.find_all("input", attrs={"name": re.compile("code")}) )
    inputs.append( soup.find_all("input", attrs={"name": re.compile("pass")}) )
    inputs_ = list( filter(None, inputs) ) # remove all empty []
    # print("inputs_: ", inputs_)
    if inputs_:
        return inputs_[0] # return 0-th element
    else:
        return inputs_


def footer_a_tags_suspicious(footer):
    footer_a_tags_suspicious_list = footer.find('a', attrs={'href': '', 'href': '#'}) # , 'href': re.compile('^#')
    # print("\n footer_a_tags_suspicious: ", footer_a_tags_suspicious_list)
    return footer_a_tags_suspicious_list


def copyright_check_impersonation(url, soup): # checks copyright and url correlation
    copyright = soup.find_all("copyright")
    if copyright:
        # print("\n copyright: ", copyright)
        copyright = str(copyright.lower()).split(" ")
        for word in copyright:
            if word in url:
                return False
    else:
        copyright = soup.find_all("©")
        # print("\n copyright: ", copyright)
        copyright = str(copyright.lower()).split(" ")
        for word in copyright:
            if word in url:
                return False
    return True
    

def domain_with_copyright(domain, content):
    content = str(content)
    m = re.search(u'(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})', content)
    _copyright = content[m.span()[0]-50:m.span()[0]+50]
    if domain.lower() in _copyright.lower():
        return True, _copyright
    else:
        return False, _copyright 


def count_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True)
        redirect_count = len(response.history)
        return redirect_count
    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)
        return -1


def get_forms_1(soup, hostname, domain):
    Form = {'internals': [], 'null': [], 'externals': []}
    # collect all form actions 
    for form in soup.findAll('form', action=True):
        dots = [x.start(0) for x in re.finditer('\.', form['action'])]
        if hostname in form['action'] or domain in form['action'] or len(dots) == 1 or not form['action'].startswith('http'):
            if not form['action'].startswith('http'):
                if not form['action'].startswith('/'):
                    Form['internals'].append(hostname+'/'+form['action']) 
                elif form['action'] in Null_format or form['action'] == 'about:blank':
                    Form['null'].append(form['action'])  
                else:
                    Form['internals'].append(hostname+form['action'])   
        else:
            Form['externals'].append(form['action'])
    return Form


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


def fake_brand_in_path(domain, path, brands):
    for b in brands:
        if '.'+b+'.' in path and b not in domain:
            print(b)
            return b
    return None



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


# permission issues
def global_rank(domain): 
    rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
        "name": domain
    })
    
    try:
        print(rank_checker_response.text)
        return int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
    except:
        return -1






def verdict(checks):
    if 'passed' not in checks.get('Google Safe Brousing API'):
        return 'Phishing'
    if 'passed' not in checks.get('whois registered domain'):
        return 'Phishing'
    
    del checks('Google Safe Brousing API')
    del checks('whois registered domain')
    del checks('domain registration length')
    del checks('google_index')

    failed_checks = 0
    total_checks = 0

    for content_check in checks:
        if 'suspicious' in content_check:
            failed_checks+=1
        elif 'failed' in  

    
    return 'Legitimate'

