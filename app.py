#!/usr/bin/env python
from flask import Flask, abort, request, render_template, session, url_for
from uuid import uuid4
import requests
import requests.auth
import urllib
from dotenv import load_dotenv
import os

load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")


@app.route("/")
def homepage():
    authorize_url = make_authorization_url()
    return render_template("index.html", authorize_url=authorize_url)


@app.route("/reddit_callback")
def reddit_callback():
    error = request.args.get("error", "")
    if error:
        return "Error: " + error
    state = request.args.get("state", "")
    if not is_valid_state(state):
        # Uh-oh, this request wasn't started by us!
        abort(403)
    code = request.args.get("code")
    access_token = get_token(code)
    username = get_username(access_token)
    session["username"] = username
    # Note: In most cases, you'll want to store the access token, in, say,
    # a session for use in other parts of your web app.
    return render_template("index.html", username=username)


@app.route("/register")
def register():
    if "username" in session:
        return render_template("register.html", username=session["username"])
    else:
        return redirect(url_for("homepage"))  # Redirect to home if not authenticated


def make_authorization_url():
    # Generate a random string for the state parameter
    # Save it for use later to prevent xsrf attacks
    state = str(uuid4())
    save_created_state(state)
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "state": state,
        "redirect_uri": REDIRECT_URI,
        "duration": "temporary",
        "scope": "identity",
    }
    url = "https://ssl.reddit.com/api/v1/authorize?" + urllib.parse.urlencode(params)
    return url


# Left as an exercise to the reader.
# You may want to store valid states in a database or memcache.
def save_created_state(state):
    pass


def is_valid_state(state):
    return True


def get_token(code):
    client_auth = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    post_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    headers = base_headers()
    response = requests.post(
        "https://ssl.reddit.com/api/v1/access_token",
        auth=client_auth,
        headers=headers,
        data=post_data,
    )
    token_json = response.json()
    return token_json["access_token"]


def get_username(access_token):
    headers = base_headers()
    headers.update({"Authorization": "bearer " + access_token})
    response = requests.get("https://oauth.reddit.com/api/v1/me", headers=headers)
    me_json = response.json()
    return me_json["name"]


def user_agent():
    """reddit API clients should each have their own, unique user-agent
    Ideally, with contact info included."""
    return "Secret Santa app by u/UnemployedTechie2021"


def base_headers():
    return {"User-Agent": user_agent()}


if __name__ == "__main__":
    app.run(debug=True, port=65010)