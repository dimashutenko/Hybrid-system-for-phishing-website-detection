import os
from flask import Flask, render_template

app = Flask(__name__)


@app.route('/')
def main():
    return render_template("index.html")


@app.route("/component1")
def component_url():
    return render_template("component_url.html")


if __name__ == '__main__':
    app.run()
