import os
from flask import Flask, render_template, request
from bs4 import BeautifulSoup
import requests

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
        return str(soup)
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
