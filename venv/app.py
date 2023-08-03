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

from heuristic_functions import check_identity
from heuristic_functions import get_inputs
from heuristic_functions import footer_a_tags_suspicious
from heuristic_functions import title_and_copyright_check_impersonation
from heuristic_functions import is_URL_accessible
from heuristic_functions import parse_url
from heuristic_functions import getPageContent
from heuristic_functions import count_redirects
from heuristic_functions import get_forms
from heuristic_functions import favicon_external_source
from heuristic_functions import domain_registration_length
from heuristic_functions import google_index
from heuristic_functions import *


from heuristic_functions import verdict


app = Flask(__name__)


def check_blacklisted(input_url):
    print("\n input_url: ", input_url)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyD5_odg6Etmv_f5coTMEHJpm6GeUDIXFcs"
    payload = "{ 'client': {'clientId':'Dmytro_Shutenko','clientVersion':'1.0.2'}, 'threatInfo': {'threatTypes':['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'], 'platformTypes':['ANY_PLATFORM'],'threatEntryTypes': ['URL'], 'threatEntries': [ {'url': '" + input_url + "'} ] } }"
    headers = {'Content-Type': 'application/json'}

    response = requests.request("POST", url, headers=headers, data=payload)
    print("\n Google API matches: ", response.text)

    if "matches" in response.text:
        return True
    else:
        return False



@app.route('/')
def main():
    return render_template("index.html")


@app.route("/component1")
def component_url():
    return render_template("component_url.html")


@app.route("/component2", methods=["GET", "POST"])
def component_dom():
    if request.method == "POST":
        url = request.form.get("url")
        if check_blacklisted(url): # if match found
            print("Blacklisted url: ", url)
            return render_template("component_dom.html",
                input_url = str(url),
                message = str("PHISHING DETECTED by Google Safe Brousing API") ) # given url is blacklisted by Google, validation stopped
        try:
            if is_URL_accessible(url):
                content = getPageContent(url)
        except:
            return render_template("component_dom.html",
                message = str(url + ' not resolved'))
        
        if content != None:
            soup = BeautifulSoup(content, 'html.parser')
            hostname, domain, path = parse_url(url)
            checks = {}

            # app.logger.debug(soup.prettify())

            try:
                inputs = get_inputs(soup) # component with input presence checks
                checks['inputs'] = 'passed' if inputs else 'suspicious'
            except:
                checks['inputs'] = 'failed'

            try:
                checks['<a> tags'] = 'suspicious' if len(soup.find_all("a")) == 0 else 'passed'
            except:
                checks['<a> tags'] = 'failed'

            if soup.find_all("a") != None:
                try:
                    checks['suspicious <a> tags in footer'] = 'passed'
                    for footer_tag in soup.select('footer, div#footer, .footer'):
                        #print("\n footer_tag: ", footer_tag)
                        if footer_a_tags_suspicious(footer_tag):
                            # for footer_a_tag_suspicious in footer_a_tags_suspicious:
                            #     print("tag", footer_a_tag_suspicious, " is suspicious")
                            checks['suspicious <a> tags in footer'] = 'suspicious'
                except:
                    print("no footer detected")
                    checks['suspicious <a> tags in footer'] = 'failed'
            else:
                print("no <a> tags detected")
                checks['suspicious <a> tags in footer'] = 'failed'
                                
            try:
                checks['redirects'] = 'passed' if count_redirects(url) < 3 else 'suspicious'
            except:
                checks['redirects'] = 'failed'

            try:
                checks['forms'] = 'suspicious' if len(get_forms(soup, hostname, domain)) > 0 else 'passed'
            except:
                checks['forms'] = 'failed'

            try:
                checks['favicon source'] = 'suspicious' if favicon_external_source(soup)  else 'passed'
            except:
                checks['favicon source'] = 'failed'

            try:
                checks['identity'] = 'passed' if check_identity(url, soup) else 'suspicious'
            except:
                checks['identity'] = 'failed'

            try:
                checks['impersonation'] = 'suspicious' if title_and_copyright_check_impersonation(url, soup) else 'passed'
            except:
                checks['impersonation'] = 'failed'

            try:
                checks['iframe'] = 'suspicious' if soup.findAll('iframe') else 'passed'
            except:
                checks['iframe'] = 'failed'

            checks['right click'] = 'suspicious' if soup.find_all(oncontextmenu=True) else 'passed'

            try:
                True
            except:
                checks['right click'] = 'failed'


            # checks['address bar'] = ''

            result = verdict(checks)
                            


            return render_template("component_dom.html",
                input_url = url, 
                checks = checks,
                result = result)
        return render_template("component_dom.html",
            input_url = url,
            message = str(url + ' not resolved')) 
        
    # default (GET), no form submition
    else:
        return render_template("component_dom.html")  


@app.route("/component3", methods=["GET", "POST"])
def component_heuristics():
    if request.method == "POST":
        url = request.form.get("url")
        if not validators.url(str(url)):
            return render_template("component_heuristics.html",
                input_url = str("URL: " + url), 
                check_1 = str("invalid url, try again") )
        
        if check_blacklisted(url): # if match found
            print("Blacklisted url: ", url)
            return render_template("component_heuristics.html",
                input_url = str(url),
                message = str("PHISHING DETECTED by Google Safe Brousing API") ) # given url is blacklisted by Google, validation stopped

        try:
            if is_URL_accessible(url):
                content = getPageContent(url)
        except:
            return render_template("component_heuristics.html",
                message = str(url + ' not resolved'))
        
        if content != None:
            soup = BeautifulSoup(content, 'html.parser')
            hostname, domain, path = parse_url(url)
            print(hostname, domain, path)
            checks = {}

            # app.logger.debug(soup.prettify())

            try:
                inputs = get_inputs(soup) # component with input presence checks
                checks['inputs'] = 'passed' if inputs else 'suspicious'
            except:
                checks['inputs'] = 'failed'

            try:
                checks['<a> tags'] = 'suspicious' if len(soup.find_all("a")) == 0 else 'passed'
            except:
                checks['<a> tags'] = 'failed'

            if soup.find_all("a") != None:
                try:
                    checks['suspicious <a> tags in footer'] = 'passed'
                    for footer_tag in soup.select('footer, div#footer, .footer'):
                        #print("\n footer_tag: ", footer_tag)
                        if footer_a_tags_suspicious(footer_tag):
                            # for footer_a_tag_suspicious in footer_a_tags_suspicious:
                            #     print("tag", footer_a_tag_suspicious, " is suspicious")
                            checks['suspicious <a> tags in footer'] = 'suspicious'
                except:
                    print("no footer detected")
                    checks['suspicious <a> tags in footer'] = 'failed'
            else:
                print("no <a> tags detected")
                checks['suspicious <a> tags in footer'] = 'failed'
                                
            try:
                checks['redirects'] = 'passed' if count_redirects(url) < 3 else 'suspicious'
            except:
                checks['redirects'] = 'failed'

            try:
                checks['forms'] = 'suspicious' if len(get_forms(soup, hostname, domain)) > 0 else 'passed'
            except:
                checks['forms'] = 'failed'

            try:
                checks['favicon source'] = 'suspicious' if favicon_external_source(soup)  else 'passed'
            except:
                checks['favicon source'] = 'failed'

            try:
                checks['identity'] = 'passed' if check_identity(url, soup) else 'suspicious'
            except:
                checks['identity'] = 'failed'

            try:
                checks['impersonation'] = 'suspicious' if title_and_copyright_check_impersonation(url, soup) else 'passed'
            except:
                checks['impersonation'] = 'failed'

            try:
                checks['iframe'] = 'suspicious' if soup.findAll('iframe') else 'passed'
            except:
                checks['iframe'] = 'failed'

            checks['right click'] = 'suspicious' if soup.find_all(oncontextmenu=True) else 'passed'

            try:
                True
            except:
                checks['right click'] = 'failed'

            try:
                checks['domain registration length'] = 'passed' if domain_registration_length(domain)>365 else 'suspicious'
            except:
                checks['domain registration length'] = 'failed'

            try:
                checks['google_index'] = 'passed' if google_index(url) else 'suspicious'
            except:
                checks['google_index']  = 'failed'




            result = verdict(checks)

            return render_template("component_heuristics.html",
                    input_url = url, 
                    checks = checks,
                    result = result)
        return render_template("component_heuristics.html",
            input_url = url,
            message = str(url + ' not resolved')) 


    # default GET, no form submition
    else:
        return render_template("component_heuristics.html") 
        

if __name__ == '__main__':
    app.run()



