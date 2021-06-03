from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# we can keep the below as env vars and make use of it
app.config['SECRET_KEY']='S3cretK3y'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)

# Database model
class Users(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(100), nullable=False)
  password = db.Column(db.String(100), nullable=False)
  email = db.Column(db.String(100),unique=True, nullable=False)
  date = db.Column(db.String(100))

# If DB not exist first request will create DB
@app.before_first_request
def create_table():
    db.create_all()

# Last login update needs to be done. Sine REST API requires login auth for each request. So holds on this part

# Basic Authentication, we can use JWT Token based Authentication for more security
def auth_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify your login', 401, {'Authenticate': 'Basic realm: "Login required"'})
        user = Users.query.filter_by(email=auth.username).first()
        if check_password_hash(user.password, auth.password):
            return f(user, *args,  **kwargs)
        return make_response('Could not verify your login', 401, {'Authenticate': 'Basic realm: "Login required"'})
    return decorator

@app.route('/register', methods=['POST'])
def register_user():
     data = request.get_json()
     hashed_password = generate_password_hash(data['password'], method='sha256')
     new_user = Users(name=data['name'], password=hashed_password, email=data['email'])
     db.session.add(new_user)
     db.session.commit()
     return jsonify({'message': 'registered successfully'})

@app.route('/profile', methods=['GET'])
@auth_required
def get_user(user):
   user = Users.query.filter_by(id=user.id).first()
   user_data = {}
   user_data['name'] = user.name
   user_data['email'] = user.email
   return jsonify({'your_details': user_data})

@app.route('/delete_profile', methods=['DELETE'])
@auth_required
def delete_user(user):
    user = Users.query.filter_by(id=user.id).first()
    if not user:
       return jsonify({'message': 'Profile does not exist'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'Your profile deleted'})

@app.route('/update_profile', methods=['PUT'])
@auth_required
def update_user(user):
    data = request.get_json()
    user = Users.query.filter_by(id=user.id).first()
    flag = False
    if not user:
       return jsonify({'message': 'Profile error'})
    if 'name' in data:
        user.name = data['name']
        flag = True
    if 'password' in data:
        user.password = generate_password_hash(data['password'], method='sha256')
        flag = True
    if 'email' in data:
        user.email = data['email']
        flag = True
    if flag:
        db.session.commit()
        return jsonify({'message': 'Your profile updated'})
    else:
        return jsonify({'message': 'Update not done, check inputs'})

if  __name__ == '__main__':
     app.run(host='localhost', port=5000)
