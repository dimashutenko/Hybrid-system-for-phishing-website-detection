import os
from flask import Flask, render_template, request
from bs4 import BeautifulSoup
import requests
import re

app = Flask(__name__)


@app.route('/')
def main():
    return render_template("index.html")


@app.route("/component1")
def component_url():
    return render_template("component_url.html")


@app.route("/component2", methods=["GET", "POST"])
def component_dom():
    url = request.args.get('url')
    q = request.args.get("q")
    if url:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # app.logger.debug(soup.prettify())
        inputs = soup.find_all("input", attrs={"name": re.compile("name")})  # finds all the input tags that have attribute "name" names contain value "name"
        inputs.append( soup.find_all("input", attrs={"name": re.compile("mail")}) )
        inputs.append( soup.find_all("input", attrs={"name": re.compile("login")}) )
        inputs.append( soup.find_all("input", attrs={"name": re.compile("id")}) )
        inputs.append( soup.find_all("input", attrs={"name": re.compile("phone")}) )
        inputs.append( soup.find_all("input", attrs={"name": re.compile("code")}) )
        inputs_2 = list( filter(None, inputs) ) # remove all empty []
        
        # print("\n", inputs_2)

        try:
            if inputs_2[0]: # if list not empty
                print("Check 2: <input>s detected, validation goes on")

                a_tag_s = soup.find_all("a") 
                #print(a_tag_s)
                if a_tag_s:
                    
                    footer_tag = soup.find_all('footer')
                    footer_tag.append( soup.find_all('div', class_= re.compile('footer')) )
                    footer_tag.append( soup.find_all('div', id= re.compile('footer')) )
                    footer_tag_s = list( filter(None, footer_tag) ) # remove all empty []
                    print(footer_tag_s)

                    # 3. перевірка адрес посилань в <footer> (атрибут “href” тегу <a> пустий або “#[будь що]” - підозра фішингу)
                    # 4.  інформація про авторські права та контент тегу <title> (перевірка значень в білих списках)
                    # 5.  “самоідентичність” сайту (якщо більша кількість посилань спрямовані на ресурси неафілійовані з доменом - підозра фішингу)


                    return render_template("component_dom.html", check_2 = str("Check 2: <input> tags detected, validation goes on"), check_3 = str("Check 3:  <a> tags are detected, validation goes on") )
                    


                else:
                    return render_template("component_dom.html", check_2 = str("Check 2: <input> tags detected, validation goes on"), check_3 = str("Check 3: not a single <a> is detected, PHISHING SUSPECTED") )
            else:
                return render_template("component_dom.html", check_2 = str("No <input> tags detected, validation stopped") )
        except:
            print("An exception occurred")
            return render_template("component_dom.html", check_2 = str("Error, check logs") )

        # if inputs_2[0]:
        #     print("continue")
        # else:
        #     return render_template("component_dom.html", check_2 = str("No <input>s detected, validation stopped") )

    elif q:
        return q
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
