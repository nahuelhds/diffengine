import logging
import os

import feedparser
import yaml
from envyaml import EnvYAML

from diffengine.utils import request_pin_to_user_and_get_token


def load_config(home, prompt=True):
    config = {}
    config_file = os.path.join(home, "config.yaml")
    env_file = os.path.join(home, ".env")
    if os.path.isfile(config_file):
        logging.debug("config exists at file %s" % config_file)
        config = EnvYAML(
            config_file, env_file=env_file if os.path.isfile(env_file) else None
        )
    else:
        logging.debug("creating config to file %s" % config_file)
        if not os.path.isdir(home):
            os.makedirs(home)
        if prompt:
            config = get_initial_config(home)
        yaml.dump(config, open(config_file, "w"), default_flow_style=False)
    return config


def get_initial_config(home):
    config = {"feeds": []}

    while len(config["feeds"]) == 0:
        url = input("What RSS/Atom feed would you like to monitor? ")
        feed = feedparser.parse(url)
        if len(feed.entries) == 0:
            print("Oops, that doesn't look like an RSS or Atom feed.")
        else:
            config["feeds"].append({"url": url, "name": feed.feed.title})

    answer = input("Would you like to set up tweeting edits? [Y/n] ") or "Y"
    if answer.lower() == "y":
        print("Go to https://apps.twitter.com and create an application.")
        consumer_key = input("What is the consumer key? ")
        consumer_secret = input("What is the consumer secret? ")

        token = request_pin_to_user_and_get_token(consumer_key, consumer_secret)

        config["twitter"] = {
            "consumer_key": consumer_key,
            "consumer_secret": consumer_secret,
        }
        config["feeds"][0]["twitter"] = {
            "access_token": token[0],
            "access_token_secret": token[1],
        }

    answer = input("Would you like to set up emailing edits? [Y/n] ")
    if answer.lower() == "y":
        print("Go to https://app.sendgrid.com/ and get an API key.")
        api_key = input("What is the API key? ")
        sender = input("What email address is sending the email? ")
        receivers = input("Who are receiving the emails?  ")

        config["sendgrid"] = {"api_key": api_key}

        config["feeds"][0]["sendgrid"] = {"sender": sender, "receivers": receivers}

    print("Saved your configuration in %s/config.yaml" % home.rstrip("/"))
    print("Fetching initial set of entries.")

    return config
