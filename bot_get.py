from tqdm import tqdm



def get_user_id_from_username(self, username):
    if username not in self._usernames:
        self.api.search_username(username)
        self.very_small_delay()
        if "user" in self.api.last_json:
            self._usernames[username] = str(self.api.last_json["user"]["pk"])
        else:
            return None
    return self._usernames[username]


def get_username_from_user_id(self, user_id):
    user_info = self.get_user_info(user_id)
    if user_info and "username" in user_info:
        return str(user_info["username"])
    return None  # Not found


def get_user_followers(self, user_id, nfollows):
    user_id = self.convert_to_user_id(user_id)
    followers = self.api.get_total_followers(user_id, nfollows)
    return [str(item["pk"]) for item in followers][::-1] if followers else []


def get_user_following(self, user_id, nfollows=None):
    user_id = self.convert_to_user_id(user_id)
    following = self.api.get_total_followings(user_id, nfollows)
    return [str(item["pk"]) for item in following][::-1] if following else []


def search_users(self, query):
    self.api.search_users(query)
    if "users" not in self.api.last_json:
        self.logger.info("Users with %s not found." % query)
        return []
    return [str(user["pk"]) for user in self.api.last_json["users"]]
