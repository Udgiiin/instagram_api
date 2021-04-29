version = "0.117.0"
import atexit
import datetime
import logging
import os
import random
import signal
import time

from instaBot_api import utils

from ..api import API

from .bot_get import (
    get_user_followers,
    get_user_following,
    get_user_id_from_username,
    get_username_from_user_id,
    search_users,
)

current_path = os.path.abspath(os.getcwd())


class Bot(object):
    def __init__(
        self,
        base_path=current_path + "/config/",
        whitelist_file="whitelist.txt",
        blacklist_file="blacklist.txt",
        comments_file="comments.txt",
        followed_file="followed.txt",
        unfollowed_file="unfollowed.txt",
        skipped_file="skipped.txt",
        friends_file="friends.txt",
        proxy=None,
        max_likes_per_day=random.randint(50, 100),
        max_unlikes_per_day=random.randint(50, 100),
        max_follows_per_day=random.randint(50, 100),
        max_unfollows_per_day=random.randint(50, 100),
        max_comments_per_day=random.randint(50, 100),
        max_blocks_per_day=random.randint(50, 100),
        max_unblocks_per_day=random.randint(50, 100),
        max_likes_to_like=random.randint(50, 100),
        min_likes_to_like=random.randint(50, 100),
        max_messages_per_day=random.randint(50, 100),
        filter_users=False,
        filter_private_users=False,
        filter_users_without_profile_photo=False,
        filter_previously_followed=False,
        filter_business_accounts=False,
        filter_verified_accounts=False,
        max_followers_to_follow=5000,
        min_followers_to_follow=10,
        max_following_to_follow=2000,
        min_following_to_follow=10,
        max_followers_to_following_ratio=15,
        max_following_to_followers_ratio=15,
        min_media_count_to_follow=3,
        max_following_to_block=2000,
        like_delay=random.randint(300, 600),
        unlike_delay=random.randint(300, 600),
        follow_delay=random.randint(300, 600),
        unfollow_delay=random.randint(300, 600),
        comment_delay=random.randint(300, 600),
        block_delay=random.randint(300, 600),
        unblock_delay=random.randint(300, 600),
        message_delay=random.randint(300, 600),
        stop_words=("shop", "store", "free"),
        blacklist_hashtags=["#shop", "#store", "#free"],
        blocked_actions_protection=True,
        blocked_actions_sleep=True,
        blocked_actions_sleep_delay=random.randint(600, 1200),
        verbosity=True,
        device=None,
        save_logfile=True,
        log_filename=None,
        loglevel_file=logging.DEBUG,
        loglevel_stream=logging.INFO,
        log_follow_unfollow=True,
    ):
        self.api = API(
            device=device,
            base_path=base_path,
            save_logfile=save_logfile,
            log_filename=log_filename,
            loglevel_file=loglevel_file,
            loglevel_stream=loglevel_stream,
        )
        self.log_follow_unfollow = log_follow_unfollow
        self.base_path = base_path

        # self.state = BotState()

        self.delays = {
            "like": like_delay,
            "unlike": unlike_delay,
            "follow": follow_delay,
            "unfollow": unfollow_delay,
            "comment": comment_delay,
            "block": block_delay,
            "unblock": unblock_delay,
            "message": message_delay,
        }

      


        # Adjust file paths
        followed_file = os.path.join(base_path, followed_file)
        unfollowed_file = os.path.join(base_path, unfollowed_file)
        skipped_file = os.path.join(base_path, skipped_file)
        friends_file = os.path.join(base_path, friends_file)
        comments_file = os.path.join(base_path, comments_file)
        blacklist_file = os.path.join(base_path, blacklist_file)
        whitelist_file = os.path.join(base_path, whitelist_file)

        # Database files
        self.followed_file = utils.file(followed_file)
        self.unfollowed_file = utils.file(unfollowed_file)
        self.skipped_file = utils.file(skipped_file)
        self.friends_file = utils.file(friends_file)
        self.comments_file = utils.file(comments_file)
        self.blacklist_file = utils.file(blacklist_file)
        self.whitelist_file = utils.file(whitelist_file)

        self.proxy = proxy
        self.verbosity = verbosity

        self.logger = self.api.logger
        self.logger.info("Instabot version: " + version + " Started")
        self.logger.debug("Bot imported from {}".format(__file__))

    @property
    def user_id(self):
        # For compatibility
        return self.api.user_id

    @property
    def username(self):
        # For compatibility
        return self.api.username

    @property
    def password(self):
        # For compatibility
        return self.api.password

    @property
    def last_json(self):
        # For compatibility
        return self.api.last_json

    @property
    def blacklist(self):
        # This is a fast operation because
        # `get_user_id_from_username` is cached.
        return [
            self.convert_to_user_id(i)
            for i in self.blacklist_file.list
            if i is not None
        ]

    @property
    def whitelist(self):
        # This is a fast operation because
        # `get_user_id_from_username` is cached.
        return [
            self.convert_to_user_id(i)
            for i in self.whitelist_file.list
            if i is not None
        ]

    @property
    def following(self):
        now = time.time()
        last = self.last.get("updated_following", now)
        if self._following is None or (now - last) > 7200:
            self.console_print("`bot.following` is empty, will download.", "green")
            self._following = self.get_user_following(self.user_id)
            self.last["updated_following"] = now
        return self._following

    @property
    def followers(self):
        now = time.time()
        last = self.last.get("updated_followers", now)
        if self._followers is None or (now - last) > 7200:
            self.console_print("`bot.followers` is empty, will download.", "green")
            self._followers = self.get_user_followers(self.user_id)
            self.last["updated_followers"] = now
        return self._followers

    @property
    def start_time(self):
        return self.state.start_time

    

    def logout(self, *args, **kwargs):
        self.api.logout()
        self.logger.info(
            "Bot stopped. " "Worked: %s", datetime.datetime.now() - self.start_time
        )
        self.print_counters()

    def login(self, **args):
        """if login function is run threaded, for example in scheduled job,
        signal will fail because it 'only works in main thread'.
        In this case, you may want to call login(is_threaded=True).
        """
        if self.proxy:
            args["proxy"] = self.proxy
        if self.api.login(**args) is False:
            return False
        self.prepare()
        atexit.register(self.print_counters)
        if "is_threaded" in args:
            if args["is_threaded"]:
                return True
        signal.signal(signal.SIGTERM, self.print_counters)
        return True

    def prepare(self):
        storage = load_checkpoint(self)
        if storage is not None:
            (
                total,
                self.blocked_actions,
                self.api.total_requests,
                self.start_time,
            ) = storage

            for k, v in total.items():
                self.total[k] = v

    def print_counters(self, *args, **kwargs):
        save_checkpoint(self)
        for key, val in self.total.items():
            if val > 0:
                self.logger.info(
                    "Total {}: {}{}".format(
                        key,
                        val,
                        "/" + str(self.max_per_day[key])
                        if self.max_per_day.get(key)
                        else "",
                    )
                )
        for key, val in self.blocked_actions.items():
            if val:
                self.logger.info("Blocked {}".format(key))
        self.logger.info("Total requests: {}".format(self.api.total_requests))



    # getters
   
    def get_user_id_from_username(self, username):
        return get_user_id_from_username(self, username)


    def get_username_from_user_id(self, user_id):
        return get_username_from_user_id(self, user_id)


    def get_user_followers(self, user_id, nfollows=None):
        return get_user_followers(self, user_id, nfollows)

    def get_user_following(self, user_id, nfollows=None):
        return get_user_following(self, user_id, nfollows)


    def search_users(self, query):
        return search_users(self, query)

   

