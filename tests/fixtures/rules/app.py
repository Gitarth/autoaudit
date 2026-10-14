import os, subprocess, pickle, sqlite3, requests
from flask import Flask, request, render_template_string, send_file
from markupsafe import Markup, escape
from werkzeug.utils import secure_filename
app = Flask(__name__)
db = sqlite3.connect("x")

@app.route("/sqli")
def sqli():
    name = request.args.get("name")
    db.cursor().execute("SELECT * FROM u WHERE n = '%s'" % name)      # VULN sqli

@app.route("/sqli_safe")
def sqli_safe():
    db.cursor().execute("SELECT * FROM u WHERE n = ?", (request.args.get("name"),))   # SAFE

@app.route("/cmd")
def cmd():
    host = request.form["host"]
    os.system("ping " + host)                                          # VULN cmdi
    subprocess.run(["ping", "-c1", host])                             # SAFE (no shell)

@app.route("/file")
def file():
    fn = request.args["f"]
    open("/data/" + fn).read()                                        # VULN path
    return send_file(os.path.join("/data", secure_filename(fn)))      # SAFE

@app.route("/xss")
def xss():
    return Markup("<b>%s</b>" % request.args["q"])                    # VULN xss

@app.route("/xss_safe")
def xss_safe():
    return Markup("<b>%s</b>") % escape(request.args["q"])            # SAFE

@app.route("/ssti")
def ssti():
    return render_template_string("Hi " + request.args["n"])          # VULN code

@app.route("/pickle")
def pick():
    return pickle.loads(request.get_data())                           # VULN deser

@app.route("/ssrf")
def ssrf():
    return requests.get(request.args["url"]).text                     # VULN ssrf
