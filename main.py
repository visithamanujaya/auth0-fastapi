import uvicorn
import json

from fastapi.middleware.cors import CORSMiddleware
from config import AUTH0_DOMAIN
from errors import AuthError
from utils import requires_auth
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer


app = FastAPI()

##########################################
# Extract the JWT  from the request      #
##########################################
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")


###########################################
# Middleware to avoid CORS errors         #
###########################################
origins = [
    "http://localhost:3000"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


#####################################################
# Return User after validating and decoding the JWT #
#####################################################
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        user = await requires_auth(token)
        return user
    except AuthError as err:
        print(err)
        return None


#####################################################
# Sample protected API end point                    #
#####################################################
@app.get("/role-based/protected/api/any")
async def protected_api(user: str = Depends(get_current_user)):

    if user and user.roles:
        roles = json.loads(user.roles)
        if 'Care Provider' in roles:
            return {"message": "Hi Care Provider User..!"}
        if 'Site Admin' in roles:
            return {"message": "Hi Site Admin User..!"}
        if 'Super' in roles:
            return {"message": "Hi Super User..!"}

    raise HTTPException(status_code=401, detail="You are not allowed here....!")


#######################################################
# Sample protected Site Admin and above only API end point #
#######################################################
@app.get("/role-based/protected/api/admin")
async def protected_api(user: str = Depends(get_current_user)):

    if user and user.roles:
        roles = json.loads(user.roles)
        if 'Site Admin' in roles:
            return {"message": "Hi Site Admin User..!"}
        if 'Super Admin' in roles:
            return {"message": "Hi Super Admin User..!"}

    raise HTTPException(status_code=401, detail="You are not allowed here....!")


#######################################################
# Sample protected Super Admin only API end point           #
#######################################################
@app.get("/role-based/protected/api/super")
async def protected_api(user: str = Depends(get_current_user)):

    if user and user.roles:
        roles = json.loads(user.roles)
        if 'Super Admin' in roles:
            return {"message": "Hi Super Admin user...!"}

    raise HTTPException(status_code=401, detail="You are not allowed here....!")


if __name__ == "__main__":

    uvicorn.run(app, host="0.0.0.0", port=8000)