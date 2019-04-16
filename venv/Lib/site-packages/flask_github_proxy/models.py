import base64
from slugify import slugify
from hashlib import sha256
from flask import jsonify
import logging


class Author(object):
    """ The author models carries information about committer and data modifiers.

    .. note:: It behaves as a "static" object : its variables are private one and only getters are registered.

    :param name: Name of the user
    :type name: str
    :param email: Email of the user
    :type email: str

    :ivar name: Name of the user
    :ivar email: Email of the user
    """
    def __init__(self, name, email):
        self.__name__ = name
        self.__email__ = email

    @property
    def name(self):
        return self.__name__

    @property
    def email(self):
        return self.__email__

    def dict(self):
        """ Builds a dictionary representation of the object (eg: for JSON)

        :return: Dictionary representation of the object
        """
        return {
            "name": self.name,
            "email": self.email
        }


class ProxyError(object):
    """ Carries information for errors

    :param code: HTTP Code Error
    :type code: int
    :param message: Message to display or a dict and its key
    :type message: str or tuple

    :ivar code: HTTP Code Error
    :ivar message: Message to display

    """
    LOGGER = logging.getLogger(__name__)

    def __init__(self, code, message, step=None, context=None):
        self.code = code
        self.message = message
        self.step = step
        self.context = context

        if isinstance(message, tuple):
            # This way to work prevents failure if there is a huge issue on Github side or there is a change in API
            # errors displaying
            dic, key = message
            if key in dic:
                self.message = dic[key]
            else:
                self.message = dic

    @staticmethod
    def AdvancedJsonify(data, status_code):
        """ Advanced Jsonify Response Maker

        :param data: Data
        :param status_code: Status_code
        :return: Response
        """
        response = jsonify(data)
        response.status_code = status_code
        return response

    def response(self, callback=None):
        """ View representation of the object

        :param callback: Function to represent the error in view. Default : flask.jsonify
        :type callback: function

        :return: View
        """
        if not callback:
            callback = type(self).AdvancedJsonify
        resp = {
            "status": "error",
            "message": self.message
        }
        if self.step:
            resp["step"] = self.step

        self.LOGGER.error(self.message, extra={"step": self.step, "context": self.context})
        return callback(resp, status_code=self.code)


class File(object):
    """ File Representation

    :param path: Path of the file on the repository
    :type path: str
    :param content: Base64 encoded content of the file
    :type content: byte
    :param author: Author of the file
    :type author: Author
    :param date: Date of the modification
    :type date: str
    :param logs: Message about the modification (Usually for commit message)
    :type logs: str

    :ivar path: Path of the file on the repository
    :ivar content: Content of the file
    :ivar base64: Base64 Encoded Content of the file
    :ivar author: Author of the file
    :ivar date: Date of the modification
    :ivar sha: Sha hash of the content

    """
    def __init__(self, path, content, author, date, logs):
        self.__path__ = path
        self.__content__ = content
        self.__author__ = author
        self.__date__ = date
        self.__logs__ = logs
        self.blob = None
        self.posted = False
        self.__branch__ = None

    @property
    def branch(self):
        return self.__branch__

    @branch.setter
    def branch(self, value):
        self.__branch__ = slugify(value)

    @property
    def path(self):
        return self.__path__

    @property
    def content(self):
        return base64.decodebytes(self.__content__.encode("utf-8"))

    @property
    def author(self):
        return self.__author__

    @property
    def date(self):
        return self.__date__

    @property
    def logs(self):
        return self.__logs__

    @property
    def sha(self):
        return sha256(self.content).hexdigest()

    @property
    def base64(self):
        return self.__content__

    def dict(self):
        """ Builds a dictionary representation of the object (eg: for JSON)

        :return: Dictionary representation of the object
        """
        params = {
            prop: getattr(self, prop)
            for prop in [
                "logs", "date", "author", "sha", "path"
            ]
        }
        params["author"] = params["author"].dict()
        return params
