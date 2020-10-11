from pydantic import BaseModel
from typing import Optional


#################################
# This is a modal to store user #
#################################
class User(BaseModel):
    iss: str
    sub: str
    aud: Optional[str] = None
    iat: Optional[str] = None
    exp: Optional[str] = None
    azp: Optional[str] = None
    scope: Optional[str] = None
    roles: Optional[str] = None
