from config import ALGORITHMS, API_AUDIENCE, AUTH0_DOMAIN
from errors import AuthError
from jose import jwt
from six.moves.urllib.request import urlopen
import json
from models import User
import urllib.request as urllib2


async def requires_auth(token):
    """Determines if the Access Token is valid
    """
    ####################################################
    # Trying to call this API async, but doesn't work  #
    # Recommend to use redis to store this value       #
    ####################################################
    jsonurl = urllib2.urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")

    ####################################################
    # Here the api call originally sync                #
    ####################################################
    # jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")

    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }

    if rsa_key:
        try:
            user = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer="https://" + AUTH0_DOMAIN + "/"
            )
            ######################################
            print(user)  # Remove this debug log #
            ######################################

            return User(iss=str(user['iss']), sub=str(user['sub']),
                        aud=str(user['aud']), iat=str(user['iat']),
                        euserp=str(user['exp']), azp=str(user['azp']),
                        scope=str(user['scope']), roles=json.dumps(user['http://viz.mn/roles']))
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 "please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

    raise AuthError({"code": "invalid_header",
                     "description": "Unable to find appropriate key"}, 401)
