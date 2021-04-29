import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import random
import sys
import time
import uuid
import secrets
import pytz
import requests
import requests.utils
import six.moves.urllib as urllib

# from requests_toolbelt import MultipartEncoder
from tqdm import tqdm

from . import config, devices
from .api_login import (
    change_device_simulation,
    generate_all_uuids,
    load_uuid_and_cookie,
    login_flow,
    pre_login_flow,
    reinstall_app_simulation,
    save_uuid_and_cookie,
    set_device,
    sync_launcher,
    get_prefill_candidates,
    get_account_family,
    get_zr_token_result,
    sync_device_features,
    creatives_ar_class,
    set_contact_point_prefill,
)

from .prepare import delete_credentials, get_credentials

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

version_info = sys.version_info[0:3]
is_py2 = version_info[0] == 2
is_py3 = version_info[0] == 3
is_py37 = version_info[:2] == (3, 7)

version = "0.117.0"
current_path = os.path.abspath(os.getcwd())


class API(object):
    def __init__(
            self,
            device=None,
            base_path=current_path + "/config/",
            save_logfile=True,
            log_filename=None,
            loglevel_file=logging.DEBUG,
            loglevel_stream=logging.INFO,
    ):
        # Setup device and user_agent
        self.device = device or devices.DEFAULT_DEVICE

        self.cookie_fname = None
        self.base_path = base_path

        self.is_logged_in = False
        self.last_login = None

        self.last_response = None
        self.total_requests = 0

        # Setup logging
        # instabot_version = Bot.version()
        # self.logger = logging.getLogger("[instabot_{}]".format(instabot_version))
        self.logger = logging.getLogger("instabot version: " + version)

        if not os.path.exists(base_path):
            os.makedirs(base_path)  # create base_path if not exists

        if not os.path.exists(base_path + "/log/"):
            os.makedirs(base_path + "/log/")  # create log folder if not exists

        if save_logfile is True:
            if log_filename is None:
                log_filename = os.path.join(
                    base_path, "log/instabot_{}.log".format(id(self))
                )

            fh = logging.FileHandler(filename=log_filename)
            fh.setLevel(loglevel_file)
            fh.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s (%(module)s %(pathname)s:%(lineno)s) - %(levelname)s - %(message)s"
                )
            )

            handler_existed = False
            for handler in self.logger.handlers:
                if isinstance(handler, logging.FileHandler):
                    handler_existed = True
                    break
            if not handler_existed:
                self.logger.addHandler(fh)

        ch = logging.StreamHandler()
        ch.setLevel(loglevel_stream)
        ch.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

        handler_existed = False
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler_existed = True
                break
        if not handler_existed:
            self.logger.addHandler(ch)
        self.logger.setLevel(logging.DEBUG)

        self.last_json = None

    def set_user(self, username, password, generate_all_uuids=True, set_device=True):
        self.username = username
        self.password = password

        if set_device is True:
            self.set_device()

        if generate_all_uuids is True:
            self.generate_all_uuids()

    def get_suggested_searches(self, _type="users"):
        return self.send_request(
            "fbsearch/suggested_searches/", self.json_data({"type": _type})
        )

    def read_msisdn_header(self, usage="default"):
        data = json.dumps({"device_id": self.uuid, "mobile_subno_usage": usage})
        return self.send_request(
            "accounts/read_msisdn_header/",
            data,
            login=True,
            headers={"X-DEVICE-ID": self.uuid},
        )

    def log_attribution(self, usage="default"):
        data = json.dumps({"adid": self.advertising_id})
        return self.send_request("attribution/log_attribution/", data, login=True)

    # ====== ALL METHODS IMPORT FROM api_login ====== #
    def sync_device_features(self, login=None):
        return sync_device_features(self, login)

    def sync_launcher(self, login=None):
        return sync_launcher(self, login)

    def set_contact_point_prefill(self, usage=None, login=False):
        return set_contact_point_prefill(self, usage, login)

    def get_prefill_candidates(self, login=False):
        return get_prefill_candidates(self, login)

    def get_account_family(self):
        return get_account_family(self)

    def get_zr_token_result(self):
        return get_zr_token_result(self)

    def pre_login_flow(self):
        return pre_login_flow(self)

    def login_flow(self, just_logged_in=False, app_refresh_interval=1800):
        return login_flow(self, just_logged_in, app_refresh_interval)

    def set_device(self):
        return set_device(self)

    def generate_all_uuids(self):
        return generate_all_uuids(self)

    def reinstall_app_simulation(self):
        return reinstall_app_simulation(self)

    def change_device_simulation(self):
        return change_device_simulation(self)

    def load_uuid_and_cookie(self, load_uuid=True, load_cookie=True):
        return load_uuid_and_cookie(self, load_uuid=load_uuid, load_cookie=load_cookie)

    def save_uuid_and_cookie(self):
        return save_uuid_and_cookie(self)

    def login(
            self,
            username=None,
            password=None,
            force=False,
            proxy=None,
            use_cookie=True,
            use_uuid=True,
            cookie_fname=None,
            ask_for_code=False,
            set_device=True,
            generate_all_uuids=True,
            is_threaded=False,
    ):
        if password is None:
            username, password = get_credentials(
                base_path=self.base_path, username=username
            )

        set_device = generate_all_uuids = True
        self.set_user(username, password)
        self.session = requests.Session()

        self.proxy = proxy
        self.set_proxy()  # Only happens if `self.proxy`

        self.cookie_fname = cookie_fname
        if self.cookie_fname is None:
            fmt = "{username}_uuid_and_cookie.json"
            cookie_fname = fmt.format(username=username)
            self.cookie_fname = os.path.join(self.base_path, cookie_fname)

        cookie_is_loaded = False
        msg = "Login flow failed, the cookie is broken. Relogin again."

        if use_cookie is True:
            # try:
            if (
                    self.load_uuid_and_cookie(load_cookie=use_cookie, load_uuid=use_uuid)
                    is True
            ):
                # Check if the token loaded is valid.
                if self.login_flow(False) is True:
                    cookie_is_loaded = True
                    self.save_successful_login()
                else:
                    self.logger.info(msg)
                    set_device = generate_all_uuids = False
                    force = True

        if not cookie_is_loaded and (not self.is_logged_in or force):
            self.session = requests.Session()
            if use_uuid is True:
                if (
                        self.load_uuid_and_cookie(
                            load_cookie=use_cookie, load_uuid=use_uuid
                        )
                        is False
                ):
                    if set_device is True:
                        self.set_device()
                    if generate_all_uuids is True:
                        self.generate_all_uuids()
            self.pre_login_flow()
            data = json.dumps(
                {
                    "jazoest": str(random.randint(22000, 22999)),
                    "country_codes": '[{"country_code":"1","source":["default"]}]',
                    "phone_id": self.phone_id,
                    "_csrftoken": self.token,
                    "username": self.username,
                    "adid": "",
                    "guid": self.uuid,
                    "device_id": self.device_id,
                    "google_tokens": "[]",
                    "password": self.password,
                    # "enc_password": self.encrypt_password(self.password),
                    # "enc_password:" "#PWD_INSTAGRAM:4:TIME:ENCRYPTED_PASSWORD"
                    "login_attempt_count": "1",
                }
            )

            if self.send_request("accounts/login/", data, True):
                self.save_successful_login()
                self.login_flow(True)
                return True

            elif (
                    self.last_json.get("error_type", "") == "checkpoint_challenge_required"
            ):
                # self.logger.info("Checkpoint challenge required...")
                if ask_for_code is True:
                    solved = self.solve_challenge()
                    if solved:
                        self.save_successful_login()
                        self.login_flow(True)
                        return True
                    else:
                        self.logger.error(
                            "Failed to login, unable to solve the challenge"
                        )
                        self.save_failed_login()
                        return False
                else:
                    return False
            elif self.last_json.get("two_factor_required"):
                if self.two_factor_auth():
                    self.save_successful_login()
                    self.login_flow(True)
                    return True
                else:
                    self.logger.error("Failed to login with 2FA!")
                    self.save_failed_login()
                    return False
            else:
                self.logger.error(
                    "Failed to login go to instagram and change your password"
                )
                self.save_failed_login()
                delete_credentials(self.base_path)
                return False

    def two_factor_auth(self):
        self.logger.info("Two-factor authentication required")
        two_factor_code = input("Enter 2FA verification code: ")
        two_factor_id = self.last_json["two_factor_info"]["two_factor_identifier"]

        login = self.session.post(
            config.API_URL + "accounts/two_factor_login/",
            data={
                "username": self.username,
                "verification_code": two_factor_code,
                "two_factor_identifier": two_factor_id,
                "password": self.password,
                "device_id": self.device_id,
                "ig_sig_key_version": config.SIG_KEY_VERSION,
            },
            allow_redirects=True,
        )

        if login.status_code == 200:
            resp_json = json.loads(login.text)
            if resp_json["status"] != "ok":
                if "message" in resp_json:
                    self.logger.error("Login error: {}".format(resp_json["message"]))
                else:
                    self.logger.error(
                        ('Login error: "{}" status and' " message {}.").format(
                            resp_json["status"], login.text
                        )
                    )
                return False
            return True
        else:
            self.logger.error(
                (
                    "Two-factor authentication request returns "
                    "{} error with message {} !"
                ).format(login.status_code, login.text)
            )
            return False

    def save_successful_login(self):
        self.is_logged_in = True
        self.last_login = time.time()
        self.logger.info("Logged-in successfully as '{}'!".format(self.username))

    def save_failed_login(self):
        self.logger.info("Username or password is incorrect.")
        delete_credentials(self.base_path)
        sys.exit()

    def solve_challenge(self):
        challenge_url = self.last_json["challenge"]["api_path"][1:]
        try:
            self.send_request(challenge_url, None, login=True, with_signature=False)
        except Exception as e:
            self.logger.error("solve_challenge; {}".format(e))
            return False

        choices = self.get_challenge_choices()
        for choice in choices:
            print(choice)
        code = input("Insert choice: ")

        data = json.dumps({"choice": code})
        try:
            self.send_request(challenge_url, data, login=True)
        except Exception as e:
            self.logger.error(e)
            return False

        print("A code has been sent to the method selected, please check.")
        code = input("Insert code: ").replace(" ", "")

        data = json.dumps({"security_code": code})
        try:
            self.send_request(challenge_url, data, login=True)
        except Exception as e:
            self.logger.error(e)
            return False

        worked = (
                ("logged_in_user" in self.last_json)
                and (self.last_json.get("action", "") == "close")
                and (self.last_json.get("status", "") == "ok")
        )

        if worked:
            return True

        self.logger.error("Not possible to log in. Reset and try again")
        return False

    def get_challenge_choices(self):
        last_json = self.last_json
        choices = []

        if last_json.get("step_name", "") == "select_verify_method":
            choices.append("Checkpoint challenge received")
            if "phone_number" in last_json["step_data"]:
                choices.append("0 - Phone")
            if "email" in last_json["step_data"]:
                choices.append("1 - Email")

        if last_json.get("step_name", "") == "delta_login_review":
            choices.append("Login attempt challenge received")
            choices.append("0 - It was me")
            choices.append("0 - It wasn't me")

        if not choices:
            choices.append(
                '"{}" challenge received'.format(last_json.get("step_name", "Unknown"))
            )
            choices.append("0 - Default")

        return choices

    def logout(self, *args, **kwargs):
        if not self.is_logged_in:
            return True
        data = json.dumps({})
        self.is_logged_in = not self.send_request(
            "accounts/logout/", data, with_signature=False
        )
        return not self.is_logged_in

    def set_proxy(self):
        if getattr(self, "proxy", None):
            parsed = urllib.parse.urlparse(self.proxy)
            scheme = "http://" if not parsed.scheme else ""
            self.session.proxies["http"] = scheme + self.proxy
            self.session.proxies["https"] = scheme + self.proxy

    def send_request(
            self,
            endpoint,
            post=None,
            login=False,
            with_signature=True,
            headers=None,
            extra_sig=None,
            timeout_minutes=None,
    ):
        self.set_proxy()  # Only happens if `self.proxy`
        # TODO: fix the request_headers
        self.session.headers.update(config.REQUEST_HEADERS)
        self.session.headers.update({"User-Agent": self.user_agent})
        # print("printing headers", self.session.headers)
        if not self.is_logged_in and not login:
            msg = "Not logged in!"
            self.logger.critical(msg)
            raise Exception(msg)
        if headers:
            self.session.headers.update(headers)

        try:
            self.total_requests += 1
            if post is not None:  # POST
                if with_signature:
                    post = self.generate_signature(
                        post
                    )  # Only `send_direct_item` doesn't need a signature
                    if extra_sig is not None and extra_sig != []:
                        post += "&".join(extra_sig)
                # time.sleep(random.randint(1, 2))
                response = self.session.post(config.API_URL + endpoint, data=post)
            else:  # GET
                # time.sleep(random.randint(1, 2))
                response = self.session.get(config.API_URL + endpoint)
        except Exception as e:
            self.logger.warning(str(e))
            return False

        self.last_response = response
        if post is not None:
            self.logger.debug(
                "POST to endpoint: {} returned response: {}".format(endpoint, response)
            )
        else:
            self.logger.debug(
                "GET to endpoint: {} returned response: {}".format(endpoint, response)
            )

        if response.status_code == 200:
            try:
                self.last_json = json.loads(response.text)
                return True
            except JSONDecodeError:
                return False
        else:
            self.logger.debug(
                "Responsecode indicates error; response content: {}".format(
                    response.content
                )
            )
            if response.status_code != 404 and response.status_code != "404":
                self.logger.error(
                    "Request returns {} error!".format(response.status_code)
                )
            try:
                response_data = json.loads(response.text)
                if response_data.get(
                        "message"
                ) is not None and "feedback_required" in str(
                    response_data.get("message").encode("utf-8")
                ):
                    self.logger.error(
                        "ATTENTION!: `feedback_required`"
                        + str(response_data.get("feedback_message").encode("utf-8"))
                    )
                    try:
                        self.last_response = response
                        self.last_json = json.loads(response.text)
                    except Exception:
                        pass
                    return "feedback_required"
            except ValueError:
                self.logger.error(
                    "Error checking for `feedback_required`, "
                    "response text is not JSON"
                )
                self.logger.info("Full Response: {}".format(str(response)))
                try:
                    self.logger.info("Response Text: {}".format(str(response.text)))
                except Exception:
                    pass
            if response.status_code == 429:
                # if we come to this error, add 5 minutes of sleep everytime we hit the 429 error (aka soft bann) keep increasing untill we are unbanned
                if timeout_minutes is None:
                    timeout_minutes = 0
                if timeout_minutes == 15:
                    # If we have been waiting for more than 15 minutes, lets restart.
                    time.sleep(1)
                    self.logger.error(
                        "Since we hit 15 minutes of time outs, we have to restart. Removing session and cookies. Please relogin."
                    )
                    delete_credentials(self.base_path)
                    sys.exit()
                timeout_minutes += 5
                self.logger.warning(
                    "That means 'too many requests'. I'll go to sleep "
                    "for {} minutes.".format(timeout_minutes)
                )
                time.sleep(timeout_minutes * 60)
                return self.send_request(
                    endpoint,
                    post,
                    login,
                    with_signature,
                    headers,
                    extra_sig,
                    timeout_minutes,
                )
            if response.status_code == 400:
                response_data = json.loads(response.text)
                if response_data.get("challenge_required"):
                    # Try and fix the challenge required error by totally restarting
                    self.logger.error(
                        "Failed to login go to instagram and change your password"
                    )
                    delete_credentials(self.base_path)
                # PERFORM Interactive Two-Factor Authentication
                if response_data.get("two_factor_required"):
                    try:
                        self.last_response = response
                        self.last_json = json.loads(response.text)
                    except Exception:
                        self.logger.error("Error unknown send request 400 2FA")
                        pass
                    return self.two_factor_auth()
                # End of Interactive Two-Factor Authentication
                else:
                    msg = "Instagram's error message: {}"
                    self.logger.info(msg.format(response_data.get("message")))
                    if "error_type" in response_data:
                        msg = "Error type: {}".format(response_data["error_type"])
                    self.logger.info(msg)

            # For debugging
            try:
                self.last_response = response
                self.last_json = json.loads(response.text)
            except Exception:
                self.logger.error("Error unknown send request")
                pass
            return False

    @property
    def cookie_dict(self):
        return self.session.cookies.get_dict()

    @property
    def token(self):
        return self.cookie_dict["csrftoken"]

    @property
    def user_id(self):
        return self.cookie_dict["ds_user_id"]

    @property
    def mid(self):
        return self.cookie_dict["mid"]

    @property
    def sessionid(self):
        return self.cookie_dict["sessionid"]

    @property
    def views(self):
        return self.cookie_dict["views"]

    @property
    def rank_token(self):
        return "{}_{}".format(self.user_id, self.uuid)

    @property
    def default_data(self):
        return {"_uuid": self.uuid, "_uid": self.user_id, "_csrftoken": self.token}

    def json_data(self, data=None):
        """Adds the default_data to data and dumps it to a json."""
        if data is None:
            data = {}
        data.update(self.default_data)
        return json.dumps(data)

    def action_data(self, data):
        _data = {"radio_type": "wifi-none", "device_id": self.device_id}
        data.update(_data)
        return data

    def auto_complete_user_list(self):
        return self.send_request("friendships/autocomplete_user_list/")

    def batch_fetch(self):

        data = {
            "surfaces_to_triggers": '{"4715":["instagram_feed_header"],"5858":["instagram_feed_tool_tip"],"5734":["instagram_feed_prompt"]}',
            # noqa
            "surfaces_to_queries": '{"4715":"Query+QuickPromotionSurfaceQuery:+Viewer+{viewer()+{eligible_promotions.trigger_context_v2(<trigger_context_v2>).ig_parameters(<ig_parameters>).trigger_name(<trigger_name>).surface_nux_id(<surface>).external_gating_permitted_qps(<external_gating_permitted_qps>).supports_client_filters(true).include_holdouts(true)+{edges+{client_ttl_seconds,log_eligibility_waterfall,is_holdout,priority,time_range+{start,end},node+{id,promotion_id,logging_data,max_impressions,triggers,contextual_filters+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}},clauses+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}},clauses+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}},clauses+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}}}}}},is_uncancelable,template+{name,parameters+{name,required,bool_value,string_value,color_value,}},creatives+{title+{text},content+{text},footer+{text},social_context+{text},social_context_images,primary_action{title+{text},url,limit,dismiss_promotion},secondary_action{title+{text},url,limit,dismiss_promotion},dismiss_action{title+{text},url,limit,dismiss_promotion},image.scale(<scale>)+{uri,width,height}}}}}}}","5858":"Query+QuickPromotionSurfaceQuery:+Viewer+{viewer()+{eligible_promotions.trigger_context_v2(<trigger_context_v2>).ig_parameters(<ig_parameters>).trigger_name(<trigger_name>).surface_nux_id(<surface>).external_gating_permitted_qps(<external_gating_permitted_qps>).supports_client_filters(true).include_holdouts(true)+{edges+{client_ttl_seconds,log_eligibility_waterfall,is_holdout,priority,time_range+{start,end},node+{id,promotion_id,logging_data,max_impressions,triggers,contextual_filters+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}},clauses+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}},clauses+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}},clauses+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}}}}}},is_uncancelable,template+{name,parameters+{name,required,bool_value,string_value,color_value,}},creatives+{title+{text},content+{text},footer+{text},social_context+{text},social_context_images,primary_action{title+{text},url,limit,dismiss_promotion},secondary_action{title+{text},url,limit,dismiss_promotion},dismiss_action{title+{text},url,limit,dismiss_promotion},image.scale(<scale>)+{uri,width,height}}}}}}}","5734":"Query+QuickPromotionSurfaceQuery:+Viewer+{viewer()+{eligible_promotions.trigger_context_v2(<trigger_context_v2>).ig_parameters(<ig_parameters>).trigger_name(<trigger_name>).surface_nux_id(<surface>).external_gating_permitted_qps(<external_gating_permitted_qps>).supports_client_filters(true).include_holdouts(true)+{edges+{client_ttl_seconds,log_eligibility_waterfall,is_holdout,priority,time_range+{start,end},node+{id,promotion_id,logging_data,max_impressions,triggers,contextual_filters+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}},clauses+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}},clauses+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}},clauses+{clause_type,filters+{filter_type,unknown_action,value+{name,required,bool_value,int_value,string_value},extra_datas+{name,required,bool_value,int_value,string_value}}}}}},is_uncancelable,template+{name,parameters+{name,required,bool_value,string_value,color_value,}},creatives+{title+{text},content+{text},footer+{text},social_context+{text},social_context_images,primary_action{title+{text},url,limit,dismiss_promotion},secondary_action{title+{text},url,limit,dismiss_promotion},dismiss_action{title+{text},url,limit,dismiss_promotion},image.scale(<scale>)+{uri,width,height}}}}}}}"}',
            "vc_policy": "default",
            "_csrftoken": self.token,
            "_uid": self.user_id,
            "_uuid": self.uuid,
            "scale": 2,
            "version": 1,
        }
        data = self.json_data(data)
        return self.send_request("qp/batch_fetch/", data)

        data = self.json_data(
            {"id": self.uuid, "experiment": "ig_android_profile_contextual_feed"}
        )
        return self.send_request("qe/expose/", data)

    # ====== FRIENDSHIPS METHODS ====== #
    def get_user_followings(self, user_id, max_id=""):
        url = (
            "friendships/{user_id}/following/?max_id={max_id}"
            "&ig_sig_key_version={sig_key}&rank_token={rank_token}"
        ).format(
            user_id=user_id,
            max_id=max_id,
            sig_key=config.SIG_KEY_VERSION,
            rank_token=self.rank_token,
        )
        return self.send_request(url)

    def get_self_users_following(self):
        return self.get_user_followings(self.user_id)

    def get_user_followers(self, user_id, max_id=""):
        url = "friendships/{user_id}/followers/?rank_token={rank_token}"
        url = url.format(user_id=user_id, rank_token=self.rank_token)
        if max_id:
            url += "&max_id={max_id}".format(max_id=max_id)
        return self.send_request(url)

    def get_self_user_followers(self):
        return self.followers

    @staticmethod
    def _prepare_recipients(users, thread_id=None, use_quotes=False):
        if not isinstance(users, list):
            print("Users must be an list")
            return False
        result = {"users": "[[{}]]".format(",".join(users))}
        if thread_id:
            template = '["{}"]' if use_quotes else "[{}]"
            result["thread"] = template.format(thread_id)
        return result

    @staticmethod
    def generate_signature(data):
        body = (
                hmac.new(
                    config.IG_SIG_KEY.encode("utf-8"), data.encode("utf-8"), hashlib.sha256
                ).hexdigest()
                + "."
                + urllib.parse.quote(data)
        )
        signature = "signed_body={body}&ig_sig_key_version={sig_key}"
        return signature.format(sig_key=config.SIG_KEY_VERSION, body=body)

    @staticmethod
    def generate_device_id(seed):
        volatile_seed = "12345"
        m = hashlib.md5()
        m.update(seed.encode("utf-8") + volatile_seed.encode("utf-8"))
        return "android-" + m.hexdigest()[:16]

    @staticmethod
    def get_seed(*args):
        m = hashlib.md5()
        m.update(b"".join([arg.encode("utf-8") for arg in args]))
        return m.hexdigest()

    @staticmethod
    def generate_UUID(uuid_type):
        generated_uuid = str(uuid.uuid4())
        if uuid_type:
            return generated_uuid
        else:
            return generated_uuid.replace("-", "")
