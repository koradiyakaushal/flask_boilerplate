from flask import current_app as app
from flask import Flask, request
from passlib.hash import pbkdf2_sha256
from jose import jwt
from main import tools
from main import auth
import json

class User:

  def __init__(self):
    self.defaults = {
      "id": tools.randID(),
      "ip_addresses": [request.remote_addr],
      "acct_active": True,
      "date_created": tools.nowDatetimeUTC(),
      "last_login": tools.nowDatetimeUTC(),
      "first_name": "",
      "last_name": "",
      "email": "",
    }
  
  def get(self):
    token_data = jwt.decode(request.headers.get('AccessToken'), app.config['SECRET_KEY'])

    user = app.db.users.find_one({ "id": token_data['user_id'] }, {
      "_id": 0,
      "password": 0
    })

    if user:
      resp = tools.JsonResp(user, 200)
    else:
      resp = tools.JsonResp({ "message": "User not found" }, 404)

    return resp
  
  def getAuth(self):
    access_token = request.headers.get("AccessToken")
    refresh_token = request.headers.get("RefreshToken")

    resp = tools.JsonResp({ "message": "User not logged in" }, 401)

    if access_token:
      try:
        decoded = jwt.decode(access_token, app.config["SECRET_KEY"])
        resp = tools.JsonResp(decoded, 200)
      except:
        resp = auth.refreshAccessToken(refresh_token)

    return resp

  def login(self):
    resp = tools.JsonResp({ "message": "Invalid user credentials" }, 403)
    
    try:
      data = json.loads(request.data)
      email = data["email"].lower()
      user = app.db.users.find_one({ "email": email }, { "_id": 0 })

      if user and pbkdf2_sha256.verify(data["password"], user["password"]):
        access_token = auth.encodeAccessToken(user["id"], user["email"])
        refresh_token = auth.encodeRefreshToken(user["id"], user["email"])

        app.db.users.update({ "id": user["id"] }, { "$set": {
          "refresh_token": refresh_token,
          "last_login": tools.nowDatetimeUTC()
        } })

        resp = tools.JsonResp({
          "id": user["id"],
          "email": user["email"],
          "first_name": user["first_name"],
          "last_name": user["last_name"],
          "access_token": access_token,
          "refresh_token": refresh_token
        }, 200)
      
    except Exception:
      pass
    
    return resp
  
  def logout(self):
    try:
      tokenData = jwt.decode(request.headers.get("AccessToken"), app.config["SECRET_KEY"])
      app.db.users.update({ "id": tokenData["user_id"] }, { '$unset': { "refresh_token": "" } })
    except:
      pass
    
    resp = tools.JsonResp({ "message": "User logged out" }, 200)

    return resp
  
  def userEmails(self):
    searchText = request.args.get("q", "")
    skip = request.args.get("skip", 0)
    limit = request.args.get("limit", 10)
    if searchText != "": 
      user = app.db.users.find({"email": {'$regex': searchText, '$options': 'i'}}, {"_id": 0, "id": 1, "email": 1 }).skip(int(skip)).limit(int(limit))
    else:
      user = app.db.users.find({}, {"_id": 0, "id": 1, "email": 1}).skip(int(skip)).limit(int(limit))
    if user:
      final_res = [i for i in user]
      resp = tools.JsonResp(final_res, 200)
    else:
      resp = tools.JsonResp({ "message": "User not found" }, 404)
    return resp
  
  def add(self):
    data = json.loads(request.data)
    expected_data = {
      "first_name": data['first_name'],
      "last_name": data['last_name'],
      "email": data['email'].lower(),
      "password": data['password']
    }

    self.defaults.update(expected_data)
    user = self.defaults
    
    user["password"] = pbkdf2_sha256.encrypt(user["password"], rounds=20000, salt_size=16)

    existing_email = app.db.users.find_one({ "email": user["email"] })

    if existing_email:
      resp = tools.JsonResp({
        "message": "There's already an account with this email address",
        "error": "email_exists"
      }, 400)
    
    else:
      if app.db.users.save(user):
        
        access_token = auth.encodeAccessToken(user["id"], user["email"])
        refresh_token = auth.encodeRefreshToken(user["id"], user["email"])

        app.db.users.update({ "id": user["id"] }, {
          "$set": {
            "refresh_token": refresh_token
          }
        })
        
        resp = tools.JsonResp({
          "id": user["id"],
          "email": user["email"],
          "first_name": user["first_name"],
          "last_name": user["last_name"],
          "access_token": access_token,
          "refresh_token": refresh_token
        }, 200)

      else:
        resp = tools.JsonResp({ "message": "User could not be added" }, 400)

    return resp