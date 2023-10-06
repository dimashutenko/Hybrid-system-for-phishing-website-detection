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
from heuristic_functions import domain_with_copyright
from heuristic_functions import is_URL_accessible
from heuristic_functions import parse_url
from heuristic_functions import getPageContent
from heuristic_functions import count_redirects
from heuristic_functions import get_forms
from heuristic_functions import favicon_external_source
from heuristic_functions import whois_registered
from heuristic_functions import domain_registration_length
from heuristic_functions import google_index
from heuristic_functions import global_rank
from heuristic_functions import fake_brand_in_path
from heuristic_functions import domain_in_title
from heuristic_functions import get_number_of_hyperlinks
from heuristic_functions import get_internal_hyperlinks_ratio
from heuristic_functions import get_null_hyperlinks_ratio
from heuristic_functions import get_external_hyperlinks_ratio
from heuristic_functions import *


from heuristic_functions import verdict

brands_file = open(os.getcwd()+"\\venv\\static\\data\\brands.txt", "r")
brands = [ line.rstrip() for line in brands_file ]


app = Flask(__name__)


def check_blacklisted(input_url):
    print("\n input_url: ", input_url)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyD5_odg6Etmv_f5coTMEHJpm6GeUDIXFcs"
    payload = "{ 'client': {'clientId':'Dmytro_Shutenko','clientVersion':'1.0.2'}, 'threatInfo': {'threatTypes':['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'], 'platformTypes':['ANY_PLATFORM'],'threatEntryTypes': ['URL'], 'threatEntries': [ {'url': '" + input_url + "'} ] } }"
    headers = {'Content-Type': 'application/json'}

    response = requests.request("POST", url, headers=headers, data=payload)
    # print("\n Google API matches: ", response.text)

    return True if "matches" in response.text else False



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
        url = url.replace("www.", "")
        if not validators.url(str(url)):
            return render_template("component_heuristics.html",
                input_url = str("URL: " + url), 
                check_1 = str("invalid url, try again") )
        
        is_blacklisted = check_blacklisted(url)
        if is_blacklisted: 
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
            # print(hostname, domain, path)
            checks = {}

            # app.logger.debug(soup.prettify())

            checks['Google Safe Brousing API'] = ['passed','Given website is not blacklisted by Google'] if not is_blacklisted else ['PHISHING']
        
            hyperlinks = get_number_of_hyperlinks(soup, domain)

            try:
                if hyperlinks['total']:
                    checks['number of hyperlinks'] = ['passed', 'number of hyperlinks is {}'.format(hyperlinks['total'])] 
                else:
                    checks['number of hyperlinks'] = ['suspicious', 'number of hyperlinks is {}'.format(hyperlinks['total'])] 
            except:
                checks['number of hyperlinks'] = ['failed']

            try:
                if not hyperlinks['internal']:
                    # checks['number of internal hyperlinks'] = ['suspicious', 'number of internal hyperlinks is {}'.format(0)]
                    checks['ratio of internal hyperlinks'] = ['suspicious', "internal hyperlinks ratio is {}".format(0)]
                else:
                    if get_internal_hyperlinks_ratio(soup, domain) > 0.5:
                        # checks['number of internal hyperlinks'] = ['passed', 'number of internal hyperlinks is {}'.format(hyperlinks['internal'])] 
                        checks['ratio of internal hyperlinks'] = ['passed', "internal hyperlinks ratio is {}".format(get_internal_hyperlinks_ratio(soup, domain))]
                    else:
                        # checks['number of internal hyperlinks'] = ['suspicious', 'number of internal hyperlinks is {}'.format(hyperlinks['internal'])] 
                        checks['ratio of internal hyperlinks'] = ['suspicious', "internal hyperlinks ratio is {}".format(get_internal_hyperlinks_ratio(soup, domain))]
            except:
                # checks['number of internal hyperlinks'] = ['failed']
                checks['ratio of internal hyperlinks'] = ['failed']
            
                
            try:
                if not hyperlinks['external']:
                    # checks['number of external hyperlinks'] = ['passed', 'number of external hyperlinks is {}'.format(0)]
                    checks['ratio of external hyperlinks'] = ['passed', "external hyperlinks ratio is {}".format(0)]
                else:
                    if get_external_hyperlinks_ratio(soup, domain) > 0.3:
                        # checks['number of external hyperlinks'] = ['suspicious', 'number of external hyperlinks is {}'.format(hyperlinks['external'])] 
                        checks['ratio of external hyperlinks'] = ['suspicious', "external hyperlinks ratio is {}".format(get_external_hyperlinks_ratio(soup, domain))]
                    else:
                        checks['ratio of external hyperlinks'] = ['passed', "external hyperlinks ratio is {}".format(get_external_hyperlinks_ratio(soup, domain))]
            except:
                # checks['number of external hyperlinks'] = ['failed']
                checks['ratio of external hyperlinks'] = ['failed']

            try:
                if not hyperlinks['null']:
                    # checks['number of null hyperlinks'] = ['passed', 'number of null hyperlinks is {}'.format(0)]
                    checks['ratio of null hyperlinks'] = ['passed', "null hyperlinks ratio is {}".format(0)]
                else:
                    # checks['number of null hyperlinks'] = ['suspicious', 'number of null hyperlinks is {}'.format(hyperlinks['null'])] 
                    if get_null_hyperlinks_ratio(soup, domain) < 0.2:
                        checks['ratio of null hyperlinks'] = ['passed', "null hyperlinks ratio is {}".format(get_null_hyperlinks_ratio(soup, domain))]
                    else:
                        checks['ratio of null hyperlinks'] = ['suspicious', "null hyperlinks ratio is {}".format(get_null_hyperlinks_ratio(soup, domain))]
            except:
                # checks['number of null hyperlinks'] = ['failed']
                checks['ratio of null hyperlinks'] = ['failed']

            try:
                domain_in_copyright, copyright_info = domain_with_copyright(domain, soup)
                checks['domain with copyright'] = ['passed', 'content around copyright: {}'.format(copyright_info)] if domain_in_copyright else ['suspicious', 'content around copyright: {}'.format(copyright_info)]
            except:
                checks['domain with copyright'] = ['failed']

            try:
                suspicious_forms = login_form(get_forms(soup, hostname, domain))
                checks['login form'] = ['suspicious', suspicious_forms] if suspicious_forms else ['passed', 'no suspicious form actions detected']
            except:
                checks['login form'] = ['failed']

            try:
                checks['favicon source'] = ['suspicious', 'favicon is loaded from an external domain'] if favicon_external_source(soup)  else ['passed', 'favicon is loaded from the same domain']
            except:
                checks['favicon source'] = ['failed']
    
            try:
                if submitting_to_email(get_forms(soup, domain, hostname)):
                    checks['submitting to email'] = ['suspicious', "form submits info to email"]
                else:
                    checks['submitting to email'] = ['passed', "form doesn't submit info to email"]
            except:
                checks['submitting to email'] = ['failed']


            try:
                checks['iframe'] = ['suspicious', '<iframe> found'] if soup.findAll('iframe') else ['passed', '<iframe> not found']
            except:
                checks['iframe'] = ['failed']

            try:
                checks['right click'] = ['suspicious', 'right click disabled'] if soup.find_all(oncontextmenu=True) else ['passed', 'right click not disabled']
            except:
                checks['right click'] = ['failed']

            # try:
            #     checks['empty title'] = ['passed', "title is '{}'".format(get_title(soup))] if get_title(soup) else ['suspicious', 'title is empty']
            # except:
            #     checks['empty title'] = ['failed']

            try:
                if domain_in_title(tldextract.extract(url).domain, soup):
                    checks['domain in title'] = ['passed', "domain {} is in the <title>".format(tldextract.extract(url).domain)]
                else:
                    checks['domain in title'] = ['suspicious', "domain {} is not in the <title>".format(tldextract.extract(url).domain)]
            except:
                checks['domain in title'] = ['failed']

            # to do -> check for pop up window




            # if soup.find_all("a") != None:
            #     try:
            #         checks['suspicious <a> tags in footer'] = ['passed']
            #         for footer_tag in soup.select('footer, div#footer, .footer'):
            #             #print("\n footer_tag: ", footer_tag)
            #             if footer_a_tags_suspicious(footer_tag):
            #                 # for footer_a_tag_suspicious in footer_a_tags_suspicious:
            #                 #     print("tag", footer_a_tag_suspicious, " is suspicious")
            #                 checks['suspicious <a> tags in footer'] = ['suspicious']
            #     except:
            #         print("no footer detected")
            #         checks['suspicious <a> tags in footer'] = ['failed']
            # else:
            #     print("no <a> tags detected")
            #     checks['suspicious <a> tags in footer'] = ['failed']

                                
            # try:
            #     if count_redirects(url) < 3:
            #         checks['redirects'] = ['passed']
            #     else:
            #         checks['redirects'] = ['suspicious']
            #     checks['redirects'] = checks['redirects'] + ['request history showed {} redirects'.format(count_redirects(url))] 
            # except:
            #     checks['redirects'] = ['failed']
     
            
            # try:
            #     checks['identity'] = ['passed'] if check_identity(url, soup) else ['suspicious']
            # except:
            #     checks['identity'] = ['failed']
            
            
            # try:
            #     res = fake_brand_in_path(domain, url, brands)
            #     if res:
            #         checks['fake brand in path'] = ['suspicious', 'fake brand {} in path detected'.format(res)] 
            #     else:
            #         checks['fake brand in path'] = ['passed', 'no fake brand in path detected']
            # except:
            #     checks['fake brand in path']  = ['failed'] 

            

            # to do -> check google index
            
            try:
                if domain_registration_length(domain)>365:
                    checks['whois registered domain'] = ['passed', 'domain resolved with whois, response: \n {}'.format(str(whois_registered(domain))[:300]+'...')]
                    checks['domain registration length'] = ['passed', 'domain registered for {} days'.format(domain_registration_length(domain))]
                else:
                    checks['whois registered domain'] = ['suspicious', 'whois response: \n {}'.format(str(whois_registered(domain))[:300]+'...')]
                    checks['domain registration length'] = ['suspicious', 'domain registered for {} days'.format(domain_registration_length(domain))]
            except:
                checks['whois registered domain'] = ['suspicious', 'domain not resolved with whois']
                checks['domain registration length'] = ['failed']

            try:
                checks['google_index'] = ['passed', 'website is indexed by Google'] if google_index(url) else ['suspicious', 'website is not indexed by Google']
            except:
                checks['google_index']  = ['failed']


            # to do -> review verdict

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



