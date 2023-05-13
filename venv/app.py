import os
from flask import Flask, render_template, request
from bs4 import BeautifulSoup
import requests
import re

app = Flask(__name__)

def component_2_check_blacklisted(input_url):
    print("\n input_url: ", input_url)
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyD5_odg6Etmv_f5coTMEHJpm6GeUDIXFcs"
    payload = "{ 'client': {'clientId':'Dmytro_Shutenko','clientVersion':'1.0.1'}, 'threatInfo': {'threatTypes':['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'], 'platformTypes':['ANY_PLATFORM'],'threatEntryTypes': ['URL'], 'threatEntries': [ {'url': '" + input_url + "'} ] } }"
    headers = {'Content-Type': 'application/json'}

    response = requests.request("POST", url, headers=headers, data=payload)
    print("\n response: ", response.text)

    if "matches" in response.text:
        return True
    else:
        return False


def component_2_check_2(soup):
    inputs = soup.find_all("input", attrs={"name": re.compile("name")})  # finds all the input tags that have attribute "name" names contain value "name"
    inputs.append( soup.find_all("input", attrs={"name": re.compile("mail")}) )
    inputs.append( soup.find_all("input", attrs={"name": re.compile("login")}) )
    inputs.append( soup.find_all("input", attrs={"name": re.compile("id")}) )
    inputs.append( soup.find_all("input", attrs={"name": re.compile("phone")}) )
    inputs.append( soup.find_all("input", attrs={"name": re.compile("code")}) )
    return list( filter(None, inputs) ) # remove all empty []


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
            print("Blacklisted link: ", url)

        response = requests.get(url)

        soup = BeautifulSoup(response.content, 'html.parser')
        # app.logger.debug(soup.prettify())
        
        # here should go component with input presence checks
        inputs = component_2_check_2(soup)
        
        print("\n inputs:", inputs)

        try:
            if inputs_2[0]: # if list not empty

                print("\n Check 2: <input>s detected, validation goes on")

                a_tag_s = soup.find_all("a") 

                # print(a_tag_s)

                if a_tag_s:
                    # footer_tag = soup.find_all('footer')
                    # footer_tag.append( soup.find_all('div', class_= re.compile('footer')) )
                    # footer_tag.append( soup.find_all('div', id= re.compile('footer')) )
                    # footer_tag_s = list( filter(None, footer_tag) ) # remove all empty []

                    # # print('\n footer_tag_s: ', footer_tag_s)

                    # footer_tag_s_unique = []

                    # for footer_tag in footer_tag_s:
                    #     if footer_tag not in footer_tag_s_unique:
                    #         footer_tag_s_unique.append(footer_tag)
                    
                    # print('\n footer_tag_s_unique: ', footer_tag_s_unique)


                    footer_tag = soup.find('div', class_= re.compile('footer'))
                    #print("\n footer_tag: ", footer_tag)

                    # footer_tags_1 = soup.find(lambda tag: tag.name in ['footer', 'div'] or tag.get('id') == 'footer' or tag.get('class') == 'footer')
                    footer_tags_1 = soup.select('footer, div#footer, .footer')
                    #print("\n footer_tags_1: ", footer_tags_1) 
                    print("\n footer_tags_1[0]: ", footer_tags_1[0])

                    if footer_tags_1:
                        for footer_tag in footer_tags_1:
                            a_tags = footer_tag.find('a', attrs={'href': '', 'href': '#'}) # , 'href': re.compile('^#')
                            if a_tags:
                                for a_tag in a_tags:
                                    print("tag", a_tag, " is suspicious")
                            else:
                                print("no suspicious <a> tags found")
                    else:
                        print("no footer detected")


                    # if footer_tag:
                    #     a_tags = footer_tag.find_all('a', attrs={'href': '', 'href': '#'})
                    #     if a_tags:
                    #         for a_tag in a_tags:
                    #             print("tag", a_tag, " is suspicious")
                    #     else:
                    #         print("no suspicious <a> tags found")
                    # else:
                    #     print("no footer detected")


                    # for footer_tag in footer_tag_s_unique:
                    #     if "href=''" in string(footer_tag):
                    #         print("phishing suspected for", footer_tag)
                    #     elif re.compile('href="#').search( string(footer_tag) ):
                    #         print("phishing suspected for", footer_tag)

                    # 3. перевірка адрес посилань в <footer> (атрибут “href” тегу <a> пустий або “#[будь що]” - підозра фішингу)
                    # 4.  інформація про авторські права та контент тегу <title> (перевірка значень в білих списках)
                    # 5.  “самоідентичність” сайту (якщо більша кількість посилань спрямовані на ресурси неафілійовані з доменом - підозра фішингу)


                    return render_template("component_dom.html", check_2 = str("Check 2: <input> tags detected, validation goes on"), check_3 = str("Check 3:  <a> tags are detected, validation goes on") )
                    


                else:
                    return render_template("component_dom.html", check_2 = str("Check 2: <input> tags detected, validation goes on"), check_3 = str("Check 3: not a single <a> is detected, PHISHING SUSPECTED") )
            else:
                return render_template("component_dom.html", check_2 = str("No <input> tags detected, validation stopped") )
        except:
            print("\n An exception occurred")
            return render_template("component_dom.html", check_2 = str("Error, check logs") )

        # if inputs_2[0]:
        #     print("continue")
        # else:
        #     return render_template("component_dom.html", check_2 = str("No <input>s detected, validation stopped") )

    else:
        return render_template("component_dom.html")


# @app.route("/url_check")
# def url_check():
#     link = request.args.get("link")
#     if not link:
#         link = ''
#     return render_template("url_check.html", link=link)


if __name__ == '__main__':
    app.run()



