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
               "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript"]


def check_identity(url, soup):
    extracted = tldextract.extract(url)
    domain = str(extracted.domain) + "." + str(extracted.suffix)
    print("\n domain: " + domain + "\n")  
    a_tags = soup.find_all("a")
    a_tags_refferencing_outside = 0
    for a_tag in a_tags:
        if str(domain) not in str(a_tag) and a_tag.get("href")[0] != '/' and a_tag.get("href")[0] != '#':
            a_tags_refferencing_outside+=1
        # else:
            # print(str(domain) + " is in " + str(a_tag))
    # print("\n Number of <a> tags refferencing outside:", a_tags_refferencing_outside)
    if a_tags_refferencing_outside > len(a_tags)/2:
        print(" more than half of <a> tags point to other domains, PHISHING SUSPECTED")
        return False
    else:
        print(str(a_tags_refferencing_outside) + " out of " + str(len(a_tags)) + " <a> tags point to other domains \n")
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
    print("\n footer_a_tags_suspicious: ", footer_a_tags_suspicious_list)
    return footer_a_tags_suspicious_list


def title_and_copyright_check_impersonation(url, soup): # checks title, copyright and url correlation
    title = soup.title.string
    print("\n title: ", title)
    title = str(title.lower()).split(" ")
    for word in title:
        if word in url:
            return False
    
    copyright = soup.find_all("copyright")
    if copyright:
        print("\n copyright: ", copyright)
        copyright = str(copyright.lower()).split(" ")
        for word in copyright:
            if word in url:
                return False
    else:
        copyright = soup.find_all("©")
        print("\n copyright: ", copyright)
        copyright = str(copyright.lower()).split(" ")
        for word in copyright:
            if word in url:
                return False
    return True
    


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



def count_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True)
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


# ------------------------------- heuristic---------

def domain_registration_length(domain):
    try:
        res = whois21.WHOIS(domain)
        expiration_date = res.expires_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            return 0
    except:
        return -1


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












# has to be weighted when all checks come into play
def verdict(checks):
    arr, passes = [value for value in checks.values()], 0
    for value in arr:
        if value == 'passed':
            passes +=1
    if passes > len(arr)/2:
        return 'website seems valid'
    return 'mild phishing probability' if passes < len(arr)/2 else 'little phishing probability'


