from flask import Blueprint, request, jsonify, Response
from copy import deepcopy
import datetime
import json
from requests import request as make_request
from flask_github_proxy.models import Author, File, ProxyError
from hashlib import sha256
import logging
from pythonjsonlogger import jsonlogger


class GithubProxy(object):
    """ Provides routes to push files to github and open pull request as a service

    Generate token : https://github.com/settings/tokens

    You can use GithubProxy.DEFAULT_BRANCH.NO and GithubProxy.DEFAULT_BRANCH.AUTO_SHA to build \
    branch name automatically.

    Default user is GithubProxy.DEFAULT_AUTHOR

    :param prefix: URI Prefix
    :param origin: Origin Repository (Repository to Pull Request From)
    :param upstream: Upstream Repository (Repository to Pull Request To)
    :param secret: Secret Key. Used to check provenance of data
    :param token: Github Authentification User Token
    :param default_branch: Default Branch to push to
    :type default_branch: str
    :param pull_req: Origin Branch to build on
    :param master_fork: Origin Repository Master Branch Name (Branch to update on the fork using the finale repositoru)
    :param master_upstream: Upstream Repository Master Branch Name (Branch to Pull Request to)
    :param app: Flask Application to connect to
    :param default_author: Default Author for Commit and Modification

    :cvar URLS: URLS routes of the proxy
    :cvar DEFAULT_AUTHOR: Default Author
    :type DEFAULT_AUTHOR: Author

    :ivar blueprint: Flask Blueprint Instance for the Extension
    :ivar prefix: Prefix of the Blueprint
    :ivar name: Name of the Blueprint
    :ivar origin: Git Repository to pull request from
    :ivar upstream: Git Repository to pull request to
    :ivar default_author: Default Author
    :type default_author: Author
    :ivar secret: Secret / Salt used to check provenance of data to be pushed
    """

    URLS = [
        ("/push/<path:filename>", "r_receive", ["POST"]),
        ("/update", "r_update", ["GET"]),
        ("/", "r_main", ["GET"])
    ]

    DEFAULT_AUTHOR = Author(
        "Github Proxy",
        "anonymous@github.com"
    )

    ProxyError = ProxyError

    class DEFAULT_BRANCH:
        """ Parameter Constant for the default_branch parameter

        :cvar NO: Default Branch is equal to origin branch
        :cvar AUTO_SHA: Generate a sha based on the file to create the branch
        """
        NO = -1
        AUTO_SHA = 0

    def __init__(self,
                 prefix, origin, upstream,
                 secret, token,
                 default_branch=None, master_upstream="master", master_fork="master",
                 app=None, default_author=None, logger=None, json_log_formatting=True):

        self.__blueprint__ = None
        self.__prefix__ = prefix
        self.__name__ = prefix.replace("/", "_").replace(".", "_")
        self.__origin__ = origin
        self.__upstream__ = upstream
        self.__secret__ = secret
        self.__urls__ = deepcopy(type(self).URLS)
        self.__default_author__ = default_author
        self.__default_branch__ = default_branch
        self.__token__ = token

        self.logger = logger or logging.getLogger(__name__)
        self.ProxyError.logger = self.logger

        if json_log_formatting is True:
            logHandler = logging.StreamHandler()
            formatter = jsonlogger.JsonFormatter()
            logHandler.setFormatter(formatter)
            self.logger.addHandler(logHandler)
            self.logger.setLevel(logging.DEBUG)

        self.master_upstream = master_upstream
        self.master_fork = master_fork

        if default_branch is None:
            self.__default_branch__ = GithubProxy.DEFAULT_BRANCH.NO

        self.github_api_url = "https://api.github.com"
        if not default_author:
            self.__default_author__ = GithubProxy.DEFAULT_AUTHOR

        self.app = None
        if app is not None:
            self.app = app
            self.init_app(self.app)

    def request(self, method, url, **kwargs):
        """ Unified method to make request to the Github API

        :param method: HTTP Method to use
        :param url: URL to reach
        :param kwargs: dictionary of arguments (params for URL parameters, data for post/put data)
        :return: Response
        """

        if "data" in kwargs:
            kwargs["data"] = json.dumps(kwargs["data"])

        kwargs["headers"] = {
            'Content-Type': 'application/json',
            'Authorization': 'token %s' % self.__token__,
        }
        req = make_request(
            method,
            url,
            **kwargs
        )
        self.logger.debug(
            "Request::{}::{}".format(method, url),
            extra={
                "request": kwargs,
                "response": {"headers": req.headers, "code": req.status_code, "data": req.content}
            }
        )
        return req

    def default_branch(self, file):
        """ Decide the name of the default branch given the file and the configuration

        :param file: File with informations about it
        :return: Branch Name
        """
        if isinstance(self.__default_branch__, str):
            return self.__default_branch__
        elif self.__default_branch__ == GithubProxy.DEFAULT_BRANCH.NO:
            return self.master_upstream
        else:
            return file.sha[:8]

    @property
    def blueprint(self):
        return self.__blueprint__

    @property
    def prefix(self):
        return self.__prefix__

    @property
    def name(self):
        return self.__name__

    @property
    def origin(self):
        return self.__origin__

    @property
    def upstream(self):
        return self.__upstream__

    @property
    def default_author(self):
        return self.__default_author__

    @property
    def secret(self):
        return self.__secret__

    def init_app(self, app):
        """ Initialize the application and register the blueprint

        :param app: Flask Application
        :return: Blueprint of the current nemo app
        :rtype: flask.Blueprint

        """
        self.app = app
        self.__blueprint__ = Blueprint(
            self.__name__,
            self.__name__,
            url_prefix=self.__prefix__,
        )

        for url, name, methods in self.__urls__:
            self.blueprint.add_url_rule(
                url,
                view_func=getattr(self, name),
                endpoint=name.replace("r_", ""),
                methods=methods
            )
        self.app = self.app.register_blueprint(self.blueprint)

        return self.blueprint

    def put(self, file):
        """ Create a new file on github

        :param file: File to create
        :return: File or self.ProxyError
        """
        input_ = {
            "message": file.logs,
            "author": file.author.dict(),
            "content": file.base64,
            "branch": file.branch
        }
        uri = "{api}/repos/{origin}/contents/{path}".format(
            api=self.github_api_url,
            origin=self.origin,
            path=file.path
        )
        data = self.request("PUT", uri, data=input_)

        if data.status_code == 201:
            file.pushed = True
            return file
        else:
            decoded_data = json.loads(data.content.decode("utf-8"))
            return self.ProxyError(
                data.status_code, (decoded_data, "message"),
                step="put", context={
                    "uri": uri,
                    "params": input_
                }
            )

    def get(self, file):
        """ Check on github if a file exists

        :param file: File to check status of
        :return: File with new information, including blob, or Error
        :rtype: File or self.ProxyError
        """
        uri = "{api}/repos/{origin}/contents/{path}".format(
            api=self.github_api_url,
            origin=self.origin,
            path=file.path
        )
        params = {
            "ref": file.branch
        }
        data = self.request("GET", uri, params=params)
        # We update the file blob because it exists and we need it for update
        if data.status_code == 200:
            data = json.loads(data.content.decode("utf-8"))
            file.blob = data["sha"]
        elif data.status_code == 404:
            pass
        else:
            decoded_data = json.loads(data.content.decode("utf-8"))
            return self.ProxyError(
                data.status_code, (decoded_data, "message"),
                step="get", context={
                    "uri": uri,
                    "params": params
                }
            )
        return file

    def update(self, file):
        """ Make an update query on Github API for given file

        :param file: File to update, with its content
        :return: File with new information, including success (or Error)
        """
        params = {
            "message": file.logs,
            "author": file.author.dict(),
            "content": file.base64,
            "sha": file.blob,
            "branch": file.branch
        }
        uri = "{api}/repos/{origin}/contents/{path}".format(
            api=self.github_api_url,
            origin=self.origin,
            path=file.path
        )
        data = self.request("PUT", uri, data=params)
        if data.status_code == 200:
            file.pushed = True
            return file
        else:
            reply = json.loads(data.content.decode("utf-8"))
            return self.ProxyError(
                data.status_code, (reply, "message"),
                step="update", context={
                    "uri": uri,
                    "params": params
                }
            )

    def pull_request(self, file):
        """ Create a pull request

        :param file: File to push through pull request
        :return: URL of the PullRequest or Proxy Error
        """
        uri = "{api}/repos/{upstream}/pulls".format(
            api=self.github_api_url,
            upstream=self.upstream,
            path=file.path
        )
        params = {
          "title": "[Proxy] {message}".format(message=file.logs),
          "body": "",
          "head": "{origin}:{branch}".format(origin=self.origin.split("/")[0], branch=file.branch),
          "base": self.master_upstream
        }
        data = self.request("POST", uri, data=params)

        if data.status_code == 201:
            return json.loads(data.content.decode("utf-8"))["html_url"]
        else:
            reply = json.loads(data.content.decode("utf-8"))
            return self.ProxyError(
                data.status_code, reply["message"],
                step="pull_request", context={
                    "uri": uri,
                    "params": params
                }
            )

    def get_ref(self, branch, origin=None):
        """ Check if a reference exists

        :param branch: The branch to check if it exists
        :return: Sha of the branch if it exists, False if it does not exist, self.ProxyError if it went wrong
        """
        if not origin:
            origin = self.origin
        uri = "{api}/repos/{origin}/git/refs/heads/{branch}".format(
            api=self.github_api_url,
            origin=origin,
            branch=branch
        )
        data = self.request("GET", uri)
        if data.status_code == 200:
            data = json.loads(data.content.decode("utf-8"))
            if isinstance(data, list):
                # No addresses matches, we get search results which stars with {branch}
                return False
            #  Otherwise, we get one record
            return data["object"]["sha"]
        elif data.status_code == 404:
            return False
        else:
            decoded_data = json.loads(data.content.decode("utf-8"))
            return self.ProxyError(
                data.status_code, (decoded_data, "message"),
                step="get_ref", context={
                    "uri": uri
                }
            )

    def make_ref(self, branch):
        """ Make a branch on github

        :param branch: Name of the branch to create
        :return: Sha of the branch or self.ProxyError
        """
        master_sha = self.get_ref(self.master_upstream)
        if not isinstance(master_sha, str):
            return self.ProxyError(
                404,
                "The default branch from which to checkout is either not available or does not exist",
                step="make_ref"
            )

        params = {
          "ref": "refs/heads/{branch}".format(branch=branch),
          "sha": master_sha
        }
        uri = "{api}/repos/{origin}/git/refs".format(
            api=self.github_api_url,
            origin=self.origin
        )
        data = self.request("POST", uri, data=params)

        if data.status_code == 201:
            data = json.loads(data.content.decode("utf-8"))
            return data["object"]["sha"]
        else:
            decoded_data = json.loads(data.content.decode("utf-8"))
            return self.ProxyError(
                data.status_code, (decoded_data, "message"),
                step="make_ref", context={
                    "uri": uri,
                    "params": params
                }
            )

    def check_sha(self, sha, content):
        """ Check sent sha against the salted hash of the content

        :param sha: SHA sent through fproxy-secure-hash header
        :param content: Base 64 encoded Content
        :return: Boolean indicating equality
        """
        rightful_sha = sha256(bytes("{}{}".format(content, self.secret), "utf-8")).hexdigest()
        return sha == rightful_sha

    def patch_ref(self, sha):
        """ Patch reference on the origin master branch

        :param sha: Sha to use for the branch
        :return: Status of success
        :rtype: str or self.ProxyError
        """
        uri = "{api}/repos/{origin}/git/refs/heads/{branch}".format(
            api=self.github_api_url,
            origin=self.origin,
            branch=self.master_fork
        )
        data = {
            "sha": sha,
            "force": True
        }
        reply = self.request(
            "PATCH",
            uri,
            data=data
        )
        if reply.status_code == 200:
            dic = json.loads(reply.content.decode("utf-8"))
            return dic["object"]["sha"]
        else:
            dic = json.loads(reply.content.decode("utf-8"))
            return self.ProxyError(
                reply.status_code,
                (dic, "message"),
                step="patch",
                context={
                    "uri": uri,
                    "data": data
                }
            )

    def r_receive(self, filename):
        """ Function which receives the data from Perseids

            - Check the branch does not exist
            - Make the branch if needed
            - Receive PUT from Perseids
            - Check if content exist
            - Update/Create content
            - Open Pull Request
            - Return PR link to Perseids

        It can take a "branch" URI parameter for the name of the branch

        :param filename: Path for the file
        :return: JSON Response with status_code 201 if successful.
        """
        ###########################################
        # Retrieving data
        ###########################################
        content = request.data.decode("utf-8")
        # Content checking
        if not content:
            error = self.ProxyError(300, "Content is missing")
            return error.response()

        author_name = request.args.get("author_name", self.default_author.name)
        author_email = request.args.get("author_email", self.default_author.email)
        author = Author(author_name, author_email)

        date = request.args.get("date", datetime.datetime.now().date().isoformat())
        logs = request.args.get("logs", "{} updated {}".format(author.name, filename))

        self.logger.info("Receiving query from {}".format(author_name), extra={"IP": request.remote_addr})

        ###########################################
        # Checking data security
        ###########################################
        secure_sha = None
        if "fproxy-secure-hash" in request.headers:
            secure_sha = request.headers["fproxy-secure-hash"]

        if not secure_sha or not self.check_sha(secure_sha, content):
            error = self.ProxyError(300, "Hash does not correspond with content")
            return error.response()

        ###########################################
        # Setting up data
        ###########################################
        file = File(
            path=filename,
            content=content,
            author=author,
            date=date,
            logs=logs
        )
        file.branch = request.args.get("branch", self.default_branch(file))

        ###########################################
        # Ensuring branch exists
        ###########################################
        branch_status = self.get_ref(file.branch)

        if isinstance(branch_status, self.ProxyError):  # If we have an error from github API
            return branch_status.response()
        elif not branch_status:  # If it does not exist
            # We create a branch
            branch_status = self.make_ref(file.branch)
            # If branch creation did not work
            if isinstance(branch_status, self.ProxyError):
                return branch_status.response()

        ###########################################
        # Pushing files
        ###########################################
        # Check if file exists
        # It feeds file.blob parameter, which tells us the sha of the file if it exists
        file = self.get(file)
        if isinstance(file, self.ProxyError):  # If we have an error from github API
            return file.response()

        # If it has a blob set up, it means we can update given file
        if file.blob:
            file = self.update(file)
        # Otherwise, we create it
        else:
            file = self.put(file)

        if isinstance(file, self.ProxyError):
            return file.response()
        ###########################################
        # Making pull request
        ###########################################

        pr_url = self.pull_request(file)
        if isinstance(pr_url, self.ProxyError):
            return pr_url.response()

        reply = {
            "status": "success",
            "message": "The workflow was well applied",
            "pr_url": pr_url
        }
        data = jsonify(reply)
        data.status_code = 201
        return data

    def r_update(self):
        """ Updates a fork Master

            - Check the ref of the origin repository
            - Patch reference of fork repository
            - Return status to Perseids

        :return: JSON Response with status_code 201 if successful.
        """

        # Getting Master Branch
        upstream = self.get_ref(self.master_upstream, origin=self.upstream)
        if isinstance(upstream, bool):
            return (ProxyError(
                404, "Upstream Master branch '{0}' does not exist".format(self.master_upstream),
                step="get_upstream_ref"
            )).response()
        elif isinstance(upstream, self.ProxyError):
            return upstream.response()

        # Patching
        new_sha = self.patch_ref(upstream)
        if isinstance(new_sha, self.ProxyError):
            return new_sha.response()

        self.logger.info("Updated repository {} to sha {}".format(self.origin, new_sha), extra={"former_sha": upstream})
        return jsonify({
            "status": "success",
            "commit": new_sha
        })

    def r_main(self):
        """ Main Route of the API

        :return: Response
        """
        r = jsonify({"message": "Nothing to see here"})
        r.status_code = 200
        return r
