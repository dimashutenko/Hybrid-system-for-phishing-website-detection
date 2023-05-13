import os
from flask import Flask, render_template, request
from bs4 import BeautifulSoup
import requests
import re

app = Flask(__name__)

def component_2_check_blacklisted(input_url):
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


def component_2_check_2(soup):
    inputs = soup.findAll("input", {"name" : re.compile("name", re.IGNORECASE)})  # finds all the input tags that have attribute "name" and contain value "name"
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


def component_2_check_a_tags_in_body(soup):
    return soup.find_all("a")


def footer_a_tags_suspicious(footer):
    footer_a_tags_suspicious_list = footer.find('a', attrs={'href': '', 'href': '#'}) # , 'href': re.compile('^#')
    print("\n footer_a_tags_suspicious: ", footer_a_tags_suspicious_list)
    return footer_a_tags_suspicious_list


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
        
        if component_2_check_blacklisted(url): # if match found
            print("Blacklisted url: ", url)
            return render_template("component_dom.html", check_1 = str("Check 1: given url is blacklisted by Google, validation stopped, PHISHING DETECTED") )

        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # app.logger.debug(soup.prettify())
        
        # here should go component with input presence checks
        inputs = component_2_check_2(soup)
        
        print("inputs:", inputs)

        if len(inputs) > 0:
            print("\n Check 2: <input>s detected, validation goes on")

            if component_2_check_a_tags_in_body(soup):
                footer_tag = soup.select('footer, div#footer, .footer')[0]
                if footer_tag:
                    print("\n footer_tag: ", footer_tag)
                    if footer_a_tags_suspicious(footer_tag):
                        # for footer_a_tag_suspicious in footer_a_tags_suspicious:
                        #     print("tag", footer_a_tag_suspicious, " is suspicious")
                        return render_template("component_dom.html", 
                            check_1 = str("Check 1: given url is not blacklisted by Google, validation goes on"), 
                            check_2 = str("Check 2: <input> tags detected, validation goes on"), 
                            check_3 = str("Check 3: <a> tags are detected in <body>, validation goes on"), 
                            check_4 = str("Check 4: Suspicious <a> tags are not detected in footer, validation stopped, PHISHING SUSPECTED") )
                    else:
                        print("no suspicious <a> tags found")
                        # check 4->5

                        return render_template("component_dom.html", 
                            check_1 = str("Check 1: given url is not blacklisted by Google, validation goes on"), 
                            check_2 = str("Check 2: <input> tags detected, validation goes on"), 
                            check_3 = str("Check 3: <a> tags are detected in <body>, validation goes on"), 
                            check_4 = str("Check 4: Suspicious <a> tags not detected in footer, validation goes on") )
                else:
                    print("no footer detected")
            else:
                print("no <a> tags detected in <body>")
                return render_template("component_dom.html", 
                    check_1 = str("Check 1: given url is not blacklisted by Google, validation goes on"), 
                    check_2 = str("Check 2: <input> tags detected, validation goes on"), 
                    check_3 = str("Check 3: <a> tags are not detected, validation stopped, PHISHING SUSPECTED") )
        else:
            print("no <input> tags detected in <body>")
            return render_template("component_dom.html", 
                check_1 = str("Check 1: given url is not blacklisted by Google, validation goes on"), 
                check_2 = str("Check 2: no <input> tags detected, validation stopped") )
    else:
        return render_template("component_dom.html") # default, no form submition 





        
        #             # 4.  інформація про авторські права та контент тегу <title> (перевірка значень в білих списках)
        #             # 5.  “самоідентичність” сайту (якщо більша кількість посилань спрямовані на ресурси неафілійовані з доменом - підозра фішингу)


        


# @app.route("/url_check")
# def url_check():
#     link = request.args.get("link")
#     if not link:
#         link = ''
#     return render_template("url_check.html", link=link)


if __name__ == '__main__':
    app.run()



