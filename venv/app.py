import os
from flask import Flask, render_template, request
from bs4 import BeautifulSoup
import requests
import re
import tldextract
import validators
import urllib.parse
from urllib.parse import urlparse

from heuristic_functions import is_URL_accessible
from heuristic_functions import get_domain
from heuristic_functions import getPageContent
from heuristic_functions import count_redirects
from heuristic_functions import get_forms
from heuristic_functions import favicon_external_source


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
    

def get_a_tags_number(soup):
    return len(soup.find_all("a"))

    
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
                domain = get_domain(url)
                content = getPageContent(url)
        except:
            return render_template("component_dom.html",
                message = str(url + ' not resolved'))
        
        if content != None:
            soup = BeautifulSoup(content, 'html.parser')
            hostname, domain, path = get_domain(url)
            checks = {}

            # app.logger.debug(soup.prettify())

            try:
                inputs = get_inputs(soup) # component with input presence checks
                checks['inputs'] = 'passed' if inputs else 'suspicious'
            except:
                checks['inputs'] = 'failed'

            try:
                checks['<a> tags'] = 'suspicious' if get_a_tags_number(soup) == 0 else 'passed'
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

            checks['right click'] = ''

            checks['iframe'] = ''

            checks['address bar'] = ''

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
            return render_template("component_dom.html",
                input_url = str(url),
                check_1 = str("Check 1: given url is blacklisted by Google, validation stopped, PHISHING DETECTED") )

        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        heuristic_checks(url, soup) # too much code -> import from outer file
    # default GET, no form submition
    else:
        return render_template("component_heuristics.html") 
        

if __name__ == '__main__':
    app.run()



