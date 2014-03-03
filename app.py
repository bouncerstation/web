from flask import Flask, redirect, url_for, render_template, request, session, Response, flash
from glob import glob
from functools import wraps
from urllib import urlencode
import hashlib
import json
import os
import os.path

app = Flask(__name__)
LOGDIR = "/home/znc/.znc/moddata/log"
app.secret_key = "YOU AREN'T GOING TO GET THE SUPER SECRET KEY HERE!"

@app.route('/index/')
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/donations/')
def donations():
    return render_template("donations.html")

@app.route('/faq/')
def faq():
    return render_template("faq.html")

@app.route('/who/')
def people():
    return render_template("who.html")

@app.route('/webchat/')
def webchat():
    return render_template("webchat.html")

@app.route('/instructions/')
def instruct():
    return render_template("instructions.html")

@app.route('/tos/')
def tos():
    return render_template("tos.html")

@app.route('/support/')
def support():
    return render_template('support.html')

# logs

def verify_login(username, password):
    with open("users.conf") as f:
        uc = unicode(f.read().decode('utf-8'))
    usern = "<User %s>" % username
    if usern in uc:
        uc = uc.split(usern)[1].split("</User>")[0]
        uc = uc.split("<Pass password>")[1].split("</Pass>")[0]
        uc = dict([i.strip().split(" = ") for i in uc.split("\n")][1:-1])
        password += uc["Salt"]
        return hashlib.sha256(password).hexdigest() == uc["Hash"]
    return False

def require_login(awesomef):
    @wraps(awesomef)
    def wrapped(*args, **kwargs):
        if "logged_in" not in session or not session["logged_in"]:
            return redirect(url_for("login"))
        return awesomef(*args, **kwargs)
    return wrapped

@app.route("/logs/login/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form["username"], request.form["password"]
        if verify_login(u, p):
            session["logged_in"] = True
            session["username"] = u
            return redirect(url_for("dashboard"))
        flash("Login failed.")
    return render_template("login.html")

def get_logs_for_user(u):
    files = glob("%s/%s_*.log" % (LOGDIR, u))
    files = [i.replace(LOGDIR + "/", "")[:-4] for i in files]
    files = sorted([i.split("_", 2)[1:] for i in files])
    logdict = {}
    for network, channel in files:
        if network not in logdict:
            logdict[network] = [channel]
        else:
            logdict[network].append(channel)
    return logdict

@app.route("/logs/")
@require_login
def dashboard():
    u = session["username"]
    logdict = get_logs_for_user(u)
    return render_template("dashboard.html", logs=logdict)

def get_log(user, network, channel):
    path = "%s/%s_%s_%s.log" % (LOGDIR, user, network, channel)
    with open(path) as log:
        log = log.readlines()[::-1]
    return log

#@app.route("/logs/view/<network>/<channel>/")
#@require_login
#def show_private(network, channel):
#    return render_template("log.html", log=get_log(session["username"], network, channel), path=request.path.replace("#", "%23"))

@app.route("/logs/view/<network>/<channel>/")
@app.route("/logs/view/<network>/<channel>/<order>/")
@app.route("/logs/view/<network>/<channel>/<order>/<int:limit>/")
@require_login
def show_private_raw(network, channel, limit=10000, order="reverse"):
    l = get_log(session["username"], network, channel)[:limit][::1 if order == "reverse" else -1]
    r = Response("".join(l), mimetype="text/plain")
    r.headers.add('X-Content-Type-Options', 'nosniff')
    return r

def make_public(network, channel):
    try:
        f = open("%s/%s_%s_%s.log.public" % (LOGDIR, session["username"], network, channel), "w")
        f.close()
    except:
        pass
    
def make_private(network, channel):
    try:
        p = "%s/%s_%s_%s.log.public" % (LOGDIR, session["username"], network, channel)
        if os.path.exists(p):
            os.remove(p)
    except:
        pass

def is_public(user, network, channel):
    p = "%s/%s_%s_%s.log.public" % (LOGDIR, user, network, channel)
    return os.path.exists(p)

@app.context_processor
def inject():
    return {"is_public": is_public}

@app.route("/logs/make/public/<network>/<channel>/")
@require_login
def view_mkpublic(network, channel):
    make_public(network, channel)
    return redirect(url_for("dashboard"))

@app.route("/logs/make/private/<network>/<channel>/")
@require_login
def view_mkprivate(network, channel):
    make_private(network, channel)
    return redirect(url_for("dashboard"))

#@app.route("/logs/public/<user>/<network>/<channel>/")
#def show_public(user, network, channel):
#    if is_public(user, network, channel):
#        return render_template("log.html", log=get_log(user, network, channel), path=request.path.replace("#", "%23"))
#    flash("That log is not public!")
#    return redirect(url_for("dashboard"))

@app.route("/logs/public/<user>/<network>/<channel>/")
@app.route("/logs/public/<user>/<network>/<channel>/<order>/")
@app.route("/logs/public/<user>/<network>/<channel>/<order>/<int:limit>/")
def show_public_raw(user, network, channel, limit=10000, order="reverse"):
    if is_public(user, network, channel):
        l = get_log(user, network, channel)[:limit][::1 if order != "reverse" else -1]
        r = Response("".join(l), mimetype="text/plain")
        r.headers.add('X-Content-Type-Options', 'nosniff')
        return r
    flash("That log is not public!")
    return redirect(url_for("dashboard"))

@app.route("/logs/logout/")
def logout():
    session.pop("username")
    session.pop("logged_in")
    return redirect(url_for("dashboard"))

# Mentions
@app.route("/logs/mentions/<network>/<channel>/")
@app.route("/logs/mentions/<network>/<channel>/<nickname>/")
def viewmentions(network, channel, nickname=None):
    if nickname is None:
        nickname = session["username"]
    l = get_log(session["username"], network, channel)
    msgs = [unicode(i, 'ISO-8859-1') for i in l]
    mentions = [i for i in msgs if nickname in i and "<%s>" % nickname not in i and "* %s" % nickname not in i and "***" not in i]
    r = Response("".join(mentions), mimetype="text/plain")
    r.headers.add("X-Content-Type-Options", "nosniff")
    return r

# delete requests
def is_admin():
    return session["username"] in ["fwilson", "sdamashek"]

def require_admin(plsf):
    @wraps(plsf)
    def wrappedfunc(*args, **kwargs):
        if not is_admin():
            return redirect(url_for("dashboard"))
        return plsf(*args, **kwargs)
    return wrappedfunc

@app.route('/logs/delete_request/')
@require_login
def delete_request():
    with open("deleterequest.txt") as fi:
        x = json.loads(fi.read())
    if session["username"] not in x:
        with open("deleterequest.txt", "w") as fi:
            fi.write(json.dumps(x + [session["username"]]))
        flash("Request complete.")
    else:
        flash("You've already filed a request, be patient :)")
    return redirect(url_for("dashboard"))

@app.route('/logs/request_admin/')
@require_admin
def show_requests():
    with open("deleterequest.txt") as fi:
        x = json.loads(fi.read())
    return render_template("delrequests.html", r=x)

@app.route('/logs/request_admin/approve/<username>/')
@require_admin
def approve_delete(username):
    with open("deleterequest.txt") as fi:
        x = json.loads(fi.read())
    if username not in x:
        flash("That user has not requested a log deletion")
        return redirect(url_for("show_requests"))
    x.remove(username)
    with open("/home/rubber/logmask") as fi:
        q = fi.read() + username + "*\n"
    with open("/home/rubber/logmask", "w") as fi:
        fi.write(q)
    with open("deleterequest.txt", "w") as fi:
        fi.write(json.dumps(x))
    flash("Done")
    return redirect(url_for("show_requests"))

@app.route('/logs/request_admin/deny/<username>/')
@require_admin
def decline_delete(username):
    with open("deleterequest.txt") as fi:
        x = json.loads(fi.read())
    x.remove(username)
    with open("deleterequest.txt", "w") as fi:
        fi.write(json.dumps(x))
    flash("Done")
    return redirect(url_for("show_requests"))

import logging
file_handler = logging.FileHandler('/home/rubber/flask.log')
file_handler.setLevel(logging.WARNING)
app.logger.addHandler(file_handler)
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=60708)
