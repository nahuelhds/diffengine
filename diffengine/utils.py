import os
import tweepy
import yaml


def request_pin_to_user_and_get_token(consumer_key, consumer_secret):
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.secure = True
    auth_url = auth.get_authorization_url()
    input(
        "Log in to https://twitter.com as the user you want to tweet as and hit enter."
    )
    input("Visit %s in your browser and hit enter." % auth_url)
    pin = input("What is your PIN: ")
    return auth.get_access_token(verifier=pin)


def generate_config(home, content):
    config_file = os.path.join(home, "config.yaml")

    if not os.path.isdir(home):
        os.makedirs(home)

    yaml.dump(content, open(config_file, "w"), default_flow_style=False)
