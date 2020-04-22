#!/usr/bin/env python
# -*- coding: utf-8 -*-

# maybe this module should be broken up into multiple files, or maybe not ...

UA = "diffengine/0.2.6 (+https://github.com/docnow/diffengine)"

import os
import re
import sys
import time
import bleach
import codecs
import jinja2
import shutil
import tweepy
import logging
import htmldiff
import requests
import feedparser
import readability
import unicodedata
import argparse
import yaml

from datetime import datetime
from dotenv import load_dotenv
from envyaml import EnvYAML
from peewee import *
from playhouse.migrate import SqliteMigrator, migrate
from selenium import webdriver
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode


parser = argparse.ArgumentParser()
parser.add_argument('--auth', action='store_true')

home = None
config = {}
db = SqliteDatabase(None)
browser = None

class BaseModel(Model):
    class Meta:
        database = db


class Feed(BaseModel):
    url = CharField(primary_key=True)
    name = CharField()
    created = DateTimeField(default=datetime.utcnow)

    @property
    def entries(self):
        return (Entry.select()
                .join(FeedEntry)
                .join(Feed)
                .where(Feed.url==self.url)
                .order_by(Entry.created.desc()))

    def get_latest(self, f):
        """
        Gets the feed and creates new entries for new content. The number
        of new entries created will be returned.
        """
        logging.info("fetching feed: %s", self.url)
        try:
            resp = _get(self.url)
            feed = feedparser.parse(resp.text)
        except Exception as e:
            logging.error("unable to fetch feed %s: %s", self.url, e)
            return 0
        count = 0
        for e in feed.entries:
            # note: look up with url only, because there may be
            # overlap bewteen feeds, especially when a large newspaper
            # has multiple feeds
            entry, created = Entry.get_or_create(url=e.link)
            if created:
                FeedEntry.create(entry=entry, feed=self)
                logging.info("found new entry: %s", e.link)

                if 'twitter' in f:
                    tweet_entry(entry, f['twitter'])

                count += 1
            elif len(entry.feeds.where(Feed.url == self.url)) == 0:
                FeedEntry.create(entry=entry, feed=self)
                logging.debug("found entry from another feed: %s", e.link)
                count += 1

        return count


class Entry(BaseModel):
    url = CharField()
    created = DateTimeField(default=datetime.utcnow)
    checked = DateTimeField(default=datetime.utcnow)
    tweet_status_id = BigIntegerField(null=True)

    @property
    def feeds(self):
        return (Feed.select()
                .join(FeedEntry)
                .join(Entry)
                .where(Entry.id==self.id))

    @property
    def stale(self):
        """
        A heuristic for checking new content very often, and checking
        older content less frequently. If an entry is deemed stale then
        it is worth checking again to see if the content has changed.
        """

        # never been checked before it's obviously stale
        if not self.checked:
            return True

        # time since the entry was created
        hotness = (datetime.utcnow() - self.created).seconds
        if hotness == 0:
            return True

        # time since the entry was last checked
        staleness = (datetime.utcnow() - self.checked).seconds

        # ratio of staleness to hotness
        r = staleness / float(hotness)

        # TODO: allow this magic number to be configured per feed?
        if r >= 0.2:
            logging.debug("%s is stale (r=%f)", self.url, r)
            return True

        logging.debug("%s not stale (r=%f)", self.url, r)
        return False

    def get_latest(self):
        """
        get_latest is the heart of the application. It will get the current
        version on the web, extract its summary with readability and compare
        it against a previous version. If a difference is found it will
        compute the diff, save it as html and png files, and tell Internet
        Archive to create a snapshot.

        If a new version was found it will be returned, otherwise None will
        be returned.
        """

        # make sure we don't go too fast
        time.sleep(1)

        # fetch the current readability-ized content for the page
        logging.info("checking %s", self.url)
        try:
            resp = _get(self.url)
        except Exception as e:
            logging.error("unable to fetch %s: %s", self.url, e)
            return None

        if resp.status_code != 200:
            logging.warning("Got %s when fetching %s", resp.status_code, self.url)
            return None

        doc = readability.Document(resp.text)
        title = doc.title()
        summary = doc.summary(html_partial=True)
        summary = bleach.clean(summary, tags=["p"], strip=True)
        summary = _normal(summary)

        # in case there was a redirect, and remove utm style marketing
        canonical_url = _remove_utm(resp.url)

        # get the latest version, if we have one
        versions = EntryVersion.select().where(EntryVersion.url == canonical_url).order_by(-EntryVersion.created).limit(1)
        if len(versions) == 0:
            old = None
        else:
            old = versions[0]

        # compare what we got against the latest version and create a
        # new version if it looks different, or is brand new (no old version)
        new = None

        # use _equal to determine if the summaries are the same
        if not old or old.title != title or not _equal(old.summary, summary):
            new = EntryVersion.create(
                title=title,
                url=canonical_url,
                summary=summary,
                entry=self
            )
            new.archive()
            if old:
                logging.debug("found new version %s", old.entry.url)
                diff = Diff.create(old=old, new=new)
                if not diff.generate():
                    logging.warning("html diff showed no changes: %s", self.url)
                    new.delete()
                    new = None
            else:
                logging.debug("found first version: %s", self.url)
                # Save the entry status_id inside the first entryVersion
                new.tweet_status_id = self.tweet_status_id
                new.save()
        else:
            logging.debug("content hasn't changed %s", self.url)

        self.checked = datetime.utcnow()
        self.save()

        return new


class FeedEntry(BaseModel):
    feed = ForeignKeyField(Feed)
    entry = ForeignKeyField(Entry)
    created = DateTimeField(default=datetime.utcnow)


class EntryVersion(BaseModel):
    title = CharField()
    url = CharField(index=True)
    summary = CharField()
    created = DateTimeField(default=datetime.utcnow)
    archive_url = CharField(null=True)
    entry = ForeignKeyField(Entry, backref='versions')
    tweet_status_id = BigIntegerField(null=True)

    @property
    def diff(self):
        """
        The diff that this version created. It can be None if
        this is the first version of a given entry.
        """
        try:
            return Diff.select().where(Diff.new_id==self.id).get()
        except:
            return None

    @property
    def next_diff(self):
        """
        The diff that this version participates in as the previous
        version. I know that's kind of a tongue twister. This can be
        None if this version is the latest we know about.
        """
        try:
            return Diff.select().where(Diff.old_id==self.id).get()
        except:
            return None

    @property
    def html(self):
        return "<h1>%s</h1>\n\n%s" % (self.title, self.summary)

    def archive(self):
        save_url = "https://web.archive.org/save/" + self.url
        try:
            resp = _get(save_url)
            archive_url = resp.headers.get("Content-Location")
            if archive_url:
                self.archive_url = "https://web.archive.org" + archive_url
                logging.debug("archived version at %s", self.archive_url)
                self.save()
                return self.archive_url
            else:
                logging.error("unable to get archive url from %s [%s]: %s",
                              save_url, resp.status_code, resp.headers)

        except Exception as e:
            logging.error("unexpected archive.org response for %s: %s", save_url, e)
        return None

class Diff(BaseModel):
    old = ForeignKeyField(EntryVersion, backref="prev_diffs")
    new = ForeignKeyField(EntryVersion, backref="next_diffs")
    created = DateTimeField(default=datetime.utcnow)
    tweeted = DateTimeField(null=True)
    blogged = DateTimeField(null=True)

    @property
    def url_changed(self):
        return self.old.url != self.new.url

    @property
    def title_changed(self):
        return self.old.title != self.new.title

    @property
    def summary_changed(self):
        return self.old.summary != self.new.summary

    @property
    def html_path(self):
        # use prime number to spread across directories
        path = home_path("diffs/%s/%s.html" % ((self.id % 257), self.id))
        if not os.path.isdir(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        return path

    @property
    def screenshot_path(self):
        return self.html_path.replace(".html", ".png")

    @property
    def thumbnail_path(self):
        return self.screenshot_path.replace('.png', '-thumb.png')

    def generate(self):
        if self._generate_diff_html():
            self._generate_diff_images()
            return True
        else:
            return False


    def _generate_diff_html(self):
        if os.path.isfile(self.html_path):
            return
        tmpl_path = os.path.join(os.path.dirname(__file__), "diff.html")
        logging.debug("creating html diff: %s", self.html_path)
        diff = htmldiff.render_html_diff(self.old.html, self.new.html)
        if '<ins>' not in diff and '<del>' not in diff:
            return False
        tmpl = jinja2.Template(codecs.open(tmpl_path, "r", "utf8").read())
        html = tmpl.render(
            title=self.new.title,
            url=self.old.entry.url,
            old_url=self.old.archive_url,
            old_time=self.old.created,
            new_url=self.new.archive_url,
            new_time=self.new.created,
            diff=diff
        )
        codecs.open(self.html_path, "w", 'utf8').write(html)
        return True

    def _generate_diff_images(self):
        if os.path.isfile(self.screenshot_path):
            return

        logging.debug("creating image screenshot %s", self.screenshot_path)
        browser.set_window_size(1400, 1000)
        uri = 'file:///' + os.path.abspath(self.html_path)
        browser.get(uri)
        time.sleep(5) # give the page time to load
        browser.save_screenshot(self.screenshot_path)
        logging.debug("creating image thumbnail %s", self.thumbnail_path)
        browser.set_window_size(800, 400)
        browser.execute_script("clip()")
        browser.save_screenshot(self.thumbnail_path)


def setup_logging():
    verbose = config.get('verbose', False)
    path = config.get('log', home_path('diffengine.log'))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        filename=path,
        filemode="a"
    )
    logging.getLogger("readability.readability").setLevel(logging.WARNING)
    logging.getLogger("tweepy.binder").setLevel(logging.WARNING)

def load_config(prompt=True):
    global config
    config_file = os.path.join(home, "config.yaml")
    if os.path.isfile(config_file):
        config = EnvYAML(config_file)
    else:
        if not os.path.isdir(home):
            os.makedirs(home)
        if prompt:
            config = get_initial_config()
        yaml.dump(config, open(config_file, "w"), default_flow_style=False)
    return config

def get_initial_config():
    config = {"feeds": []}

    while len(config['feeds']) == 0:
        url = input("What RSS/Atom feed would you like to monitor? ")
        feed = feedparser.parse(url)
        if len(feed.entries) == 0:
            print("Oops, that doesn't look like an RSS or Atom feed.")
        else:
            name = input("What is the name for this feed?")
            config['feeds'].append({
                "url": url,
                "name": name if name == '' else feed.feed.title
            })

    answer = input("Would you like to set up tweeting edits? [Y/n] ")
    if answer.lower() == "y":
        twitter_consumer_key = os.getenv("TWITTER_CONSUMER_KEY")
        twitter_consumer_secret = os.getenv("TWITTER_CONSUMER_SECRET")
        print("Go to https://apps.twitter.com and create an application.")
        consumer_key = twitter_consumer_key if twitter_consumer_key is not None else input("What is the consumer key? ")
        consumer_secret = twitter_consumer_secret if twitter_consumer_secret is not None else input("What is the consumer secret? ")
        auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
        auth.secure = True
        auth_url = auth.get_authorization_url()
        input("Log in to https://twitter.com as the user you want to tweet as and hit enter.")
        input("Visit %s in your browser and hit enter." % auth_url)
        pin = input("What is your PIN: ")
        token = auth.get_access_token(verifier=pin)
        config["twitter"] = {
            "consumer_key": consumer_key,
            "consumer_secret": consumer_secret
        }
        config["feeds"][0]["twitter"] = {
            "access_token": token[0],
            "access_token_secret": token[1]
        }

    print("Saved your configuration in %s/config.yaml" % home.rstrip("/"))
    print("Fetching initial set of entries.")

    return config

def home_path(rel_path):
    return os.path.join(home, rel_path)

def setup_db():
    global db
    db_file = config.get('db', home_path('diffengine.db'))
    logging.debug("connecting to db %s", db_file)
    db.init(db_file)
    db.connect()
    db.create_tables([Feed, Entry, FeedEntry, EntryVersion, Diff], safe=True)
    try:
        migrator = SqliteMigrator(db)
        migrate(migrator.add_index('entryversion', ('url',), False),)
    except OperationalError as e:
        logging.debug(e)


def setup_browser():
    global browser

    executable_path = 'chromedriver' if os.environ.get("CHROMEDRIVER_PATH") is None else os.environ.get("CHROMEDRIVER_PATH")
    binary_location = '' if os.environ.get("GOOGLE_CHROME_BIN") is None else os.environ.get("GOOGLE_CHROME_BIN")

    if not shutil.which(executable_path):
        sys.exit("Please install chromedriver and make sure it is in your PATH.")

    options = webdriver.ChromeOptions()
    options.binary_location = binary_location
    options.add_argument("--headless")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--no-sandbox")
    browser = webdriver.Chrome(executable_path=executable_path, options=options)


def tweet_entry(entry, token):
    if 'twitter' not in config:
        logging.debug("twitter not configured")
        return
    elif not token:
        logging.debug("access token/secret not set up for feed")
        return
    elif entry.tweet_status_id:
        logging.warning("entry %s has already been tweeted", entry.id)
        return

    t = config['twitter']
    auth = tweepy.OAuthHandler(t['consumer_key'], t['consumer_secret'])
    auth.secure = True
    auth.set_access_token(token['access_token'], token['access_token_secret'])
    twitter = tweepy.API(auth)

    try:
        status = twitter.update_status(entry.url)
        entry.tweet_status_id = status.id
        logging.info("tweeted %s", status.text)
        entry.save()
    except Exception as e:
        logging.error("unable to tweet: %s", e)


def tweet_diff(diff, token):
    if 'twitter' not in config:
        logging.debug("twitter not configured")
        return
    elif not token:
        logging.debug("access token/secret not set up for feed")
        return
    elif diff.tweeted:
        logging.warning("diff %s has already been tweeted", diff.id)
        return
    elif not (diff.old.archive_url and diff.new.archive_url):
        logging.warning("not tweeting without archive urls")
        return

    t = config['twitter']
    auth = tweepy.OAuthHandler(t['consumer_key'], t['consumer_secret'])
    auth.secure = True
    auth.set_access_token(token['access_token'], token['access_token_secret'])
    twitter = tweepy.API(auth)

    text = build_text(diff, config['lang'])

    try:
        status = twitter.update_with_media(diff.thumbnail_path, status=text, in_reply_to_status_id=diff.old.tweet_status_id)
        logging.info("tweeted %s", status.text)
        # Save the tweet status id inside the new version
        diff.new.tweet_status_id = status.id
        diff.new.save()
        # And save that the diff has been tweeted
        diff.tweeted = datetime.utcnow()
        diff.save()
    except Exception as e:
        logging.error("unable to tweet: %s", e)


def build_text(diff, lang):
    logging.debug("Building text for diff %s" % diff.new.title)
    text = None

    # Try build the text from i18n
    if all (k in lang for k in ("change_in", "the_url", "the_title", "the_summary")):
        logging.debug("Found all required lang terms!")
        try:
            return '%s\n%s' % (build_text_from_changes(lang, diff.url_changed, diff.title_changed, diff.summary_changed), diff.new.archive_url)
        except Exception as e:
            logging.error("Could not build text from lang", e)

    logging.debug("Building default text")
    # otherwise, build it as usual
    if text is None:
        text = diff.new.title
        if len(text) >= 225:
            text = text[0:225] + "…"
        text += " " + diff.old.archive_url +  " ➜ " + diff.new.archive_url

    return text


def build_text_from_changes(lang, url_changed, title_changed, summary_changed):
    changes = []
    if url_changed:
        changes.append(lang['the_url'])
    if title_changed:
        changes.append(lang['the_title'])
    if summary_changed:
        changes.append(lang['the_summary'])

    if len(changes) > 1:
        and_change = ' %s ' % lang['and']
        last_change = changes.pop(len(changes) - 1)
    else:
        and_change = ''
        last_change = ''

    return '%s %s%s%s' % (lang['change_in'], ', '.join(changes), and_change, last_change)


def init(new_home, prompt=True):
    global home
    home = new_home
    env_path = "%s/.env" % new_home
    load_dotenv(dotenv_path=env_path)
    load_config(prompt)
    setup_browser()
    setup_logging()
    setup_db()

def main():
    if len(sys.argv) == 1:
        home = os.getcwd()
    else:
        home = sys.argv[1]

    init(home)
    start_time = datetime.utcnow()
    logging.info("starting up with home=%s", home)

    checked = skipped = new = 0

    for f in config.get('feeds', []):
        feed, created = Feed.get_or_create(url=f['url'], name=f['name'])
        if created:
            logging.debug("created new feed for %s", f['url'])

        # get latest feed entries
        feed.get_latest(f)

        # get latest content for each entry
        for entry in feed.entries:
            if not entry.stale:
                skipped += 1
                continue
            checked += 1
            try:
                version = entry.get_latest()
            except Exception as e:
                logging.error('unable to get latest', e)
                continue
            if version:
                new += 1
            if version and version.diff and 'twitter' in f:
                tweet_diff(version.diff, f['twitter'])

    elapsed = datetime.utcnow() - start_time
    logging.info("shutting down: new=%s checked=%s skipped=%s elapsed=%s",
        new, checked, skipped, elapsed)

    browser.quit()

def _dt(d):
    return d.strftime("%Y-%m-%d %H:%M:%S")


def _normal(s):
    # additional normalizations for readability + bleached text
    s = s.replace("\xa0", " ")
    s = s.replace('“', '"')
    s = s.replace('”', '"')
    s = s.replace("’", "'")
    s = s.replace("\n", " ")
    s = s.replace("­", "")
    s = re.sub(r'  +', ' ', s)
    s = s.strip()
    return s

def _equal(s1, s2):
    return _fingerprint(s1) == _fingerprint(s2)

punctuation = dict.fromkeys(i for i in range(sys.maxunicode)
        if unicodedata.category(chr(i)).startswith('P'))

def _fingerprint(s):
    # make sure the string has been normalized, bleach everything, remove all
    # whitespace and punctuation to create a pseudo fingerprint for the text
    # for use during comparison
    s = _normal(s)
    s = bleach.clean(s, tags=[], strip=True)
    s = re.sub(r'\s+', '', s, flags=re.MULTILINE)
    s = s.translate(punctuation)
    return s

def _remove_utm(url):
    u = urlparse(url)
    q = parse_qs(u.query, keep_blank_values=True)
    new_q = dict((k, v) for k, v in q.items() if not k.startswith('utm_'))
    return urlunparse([
        u.scheme,
        u.netloc,
        u.path,
        u.params,
        urlencode(new_q, doseq=True),
        u.fragment
    ])

def _get(url, allow_redirects=True):
    return requests.get(
        url,
        timeout=60,
        headers={"User-Agent": UA},
        allow_redirects=allow_redirects
    )

def get_auth_link():
    global home
    home = os.getcwd()
    env_path = "%s/.env" % home
    load_dotenv(dotenv_path=env_path)
    config = load_config(True)
    twitter = config['twitter']
    auth = tweepy.OAuthHandler(twitter['consumer_key'], twitter['consumer_secret'])
    auth.secure = True
    auth_url = auth.get_authorization_url()
    input("Log in to https://twitter.com as the user you want to tweet as and hit enter.")
    print("This is the auth link %s" % auth_url)

if __name__ == "__main__":
    options = parser.parse_args()
    if options.auth:
        get_auth_link()
    else:
        main()

