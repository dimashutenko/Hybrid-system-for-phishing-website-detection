# Hybrid system for phishing website detection
 Hybrid system for phishing website detection



FLASK TUTORIAL https://flask.palletsprojects.com/en/2.3.x/tutorial/



CREATION, ACTIVATION, Flask INSTALLATION:

Virtual environments
Use a virtual environment to manage the dependencies for your project, both in development and in production.

What problem does a virtual environment solve? The more Python projects you have, the more likely it is that you need to work with different versions of Python libraries, or even Python itself. Newer versions of libraries for one project can break compatibility in another project.

Virtual environments are independent groups of Python libraries, one for each project. Packages installed for one project will not affect other projects or the operating system’s packages.

Python comes bundled with the venv module to create virtual environments.

how? -> https://flask.palletsprojects.com/en/2.3.x/installation/

CREATE ON WINDOWS
mkdir myproject
> cd myproject
> py -3 -m venv .venv

CREATE ON LINUX
$ mkdir myproject
$ cd myproject
$ python3 -m venv .venv

Activate the environment on Linux
$ . .venv/bin/activate

Activate the environment on Windows                                 !!!!!!!!!
> venv\Scripts\activate

INSTALL flask
$ pip install Flask


RUN:  flask --app app run --debug 
$ flask --app [name of file .app without extention] run [--debug is optional]