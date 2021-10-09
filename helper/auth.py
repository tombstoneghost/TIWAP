# Imports
import jwt
from datetime import datetime, timedelta


class Auth:
    __SECRET_KEY = '7H15_i5_@_s3cr37_k3Y'

    def encode_auth_token(self, username):
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(days=0, hours=1),
                'iat': datetime.utcnow(),
                'sub': username
            }

            return jwt.encode(payload, self.__SECRET_KEY, algorithm='HS256')
        except Exception as e:
            return e
