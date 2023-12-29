# Imports
import jwt
from datetime import datetime, timedelta


class Auth:
    __SECRET_KEY = '7H15_i5_@_s3cr37_k3Y'

    def encode_auth_token(self, username):
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(days=0, hours=12),
                'iat': datetime.utcnow(),
                'sub': username
            }

            return jwt.encode(payload, self.__SECRET_KEY, algorithm='HS256')
        except Exception as e:
            return e
        

    def decode_auth_token(self, token):
        return jwt.decode(token, key=self.__SECRET_KEY, algorithms=['HS256'])
        

    def insecure_auth_token(self, username):
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(days=0, hours=1),
                'iat': datetime.utcnow(),
                'sub': username
            }

            return jwt.encode(payload=payload, key="", algorithm='HS256')
        except Exception as e:
            return e

    def decode_insecure_auth_token(self, token):
        username = jwt.decode(jwt=token, key="", algorithms='HS256', options={"verify_signature": False})

        return username["sub"]
    

    def weak_auth_token(self, username):
        key = "secret"
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(days=0, hours=1),
                'iat': datetime.utcnow(),
                'sub': username
            }

            return jwt.encode(payload=payload, key=key, algorithm='HS256')
        except Exception as e:
            return e
        
    def decode_weak_auth_token(self, token):
        key = "secret"
        username = jwt.decode(jwt=token, key=key, algorithms='HS256')

        return username["sub"]
