#!/usr/bin/env python
from flask import Flask, abort, request, render_template, session, url_for
from uuid import uuid4
import requests
import requests.auth
import urllib
import re
from urllib.parse import urlparse
from dotenv import load_dotenv
import os
from supabase import create_client, Client
import random
import string


load_dotenv()

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(url, key)

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
    response = supabase.table("gifts").select("*").eq("username", username).execute()
    if response.data:
        gift_sent = 1
    else:
        gift_sent = 0
    return render_template("index.html", username=username, gift_sent=gift_sent)


@app.route("/send_gift", methods=["GET", "POST"])
def send_gift():
    if "username" not in session:
        return redirect(url_for("homepage"))

    confirmation_message = None  # Initialize a variable to hold the message

    if request.method == "POST":
        ecard_url = request.form.get("ecard_url")
        username = session["username"]

        if not ecard_url:
            confirmation_message = "Please provide a valid eCard URL!"
            return render_template(
                "send_gift.html", username=username, message=confirmation_message
            )
        
        # Validate URL
        if not is_valid_url(ecard_url):
            confirmation_message = "Invalid URL! Please provide a valid eCard URL starting with http:// or https://. Click on the back button to resend your gift with the correct URL."
            return render_template(
                "send_gift.html", username=username, message=confirmation_message
            )

        # Save gift to Supabase
        try:
            response = (
                supabase.table("gifts")
                .upsert({"username": username, "ecard_url": ecard_url})
                .execute()
            )
            confirmation_message = "Your gift has been sent successfully!"
        except Exception as e:
            confirmation_message = "Failed to send gift. Please try again later."

    return render_template(
        "send_gift.html", username=session["username"], message=confirmation_message
    )


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

def is_valid_url(url):
    """
    Validate if the URL starts with http:// or https://.
    """
    parsed_url = urlparse(url)
    return bool(parsed_url.scheme) and parsed_url.scheme in ["http", "https"] and bool(parsed_url.netloc)

if __name__ == "__main__":
    app.run(debug=True, port=65010)
