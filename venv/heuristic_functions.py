# consider adding other functions from app.py here
import urllib.parse
import tldextract
import requests
import json
import csv
import os
import re


from urllib.parse import urlparse
from bs4 import BeautifulSoup

import signal

# source https://data.mendeley.com/datasets/c2gw7fy2j4/3/files/01f5fa84-8d41-4692-9878-983f615ff1d7

Null_format = ["", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whatever",
               "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript"]


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


def get_domain(url):
    o = urllib.parse.urlsplit(url)
    return o.hostname, tldextract.extract(url).domain, o.path


def getPageContent(url):
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


def count_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True)
        print(1)
        redirect_count = len(response.history)
        return redirect_count
    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)
        return -1


def get_forms(soup, hostname, domain):
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


def favicon_external_source(soup):
    try:
        favicon_link = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        
        if favicon_link:
            favicon_url = favicon_link.get('href')
            parsed_url = urlparse(favicon_url)
            
            if parsed_url.netloc != '':
                print("Favicon is loaded from an external source:", favicon_url)
                return True
            else:
                print("Favicon is loaded from the same domain as the website.")
                return False
        else:
            print("No favicon found on the website.")
            return None
    
    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)
        return None






# has to be weighted when all checks come into play
def verdict(checks):
    arr, passes = [value for value in checks.values()], 0
    for value in arr:
        if value == 'passed':
            passes +=1
    if passes > len(arr)/2:
        return 'website seems valid'
    return 'mild phishing probability' if passes < len(arr)/2 else 'little phishing probability'
