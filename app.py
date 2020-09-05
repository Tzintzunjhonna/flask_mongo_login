from flask import Flask, request, json, jsonify, session, render_template, redirect, url_for, flash, g
from flask_pymongo import PyMongo, ObjectId
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token)


app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost/pythonreact'
app.secret_key = 'mysecretkey'
app.config['JWT_SECRET_KEY'] = 'secret'
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
db = mongo.db.users
CORS(app)
jwt = JWTManager(app)

@app.route('/')
def hola():
    return 'Hola, observa un momento el codigo para verificar las rutas'

@app.route('/index')
def index():
    if not g.user:
        return render_template('login.html')
    else:
        access = g.user
        return render_template('index.html', access=access)

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/login/access')
def login_access():
    return render_template('login.html')

@app.route('/create', methods=['POST', 'GET'])
def create():

    if request.method == 'POST':
        users = mongo.db.users
        exist = users.find_one({'email': request.form['email']})

        if exist is None:
            users.insert({
            'name': request.form['name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'],
            'password': bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
            })
            flash('Usuario registrado')
            return render_template('login.html')

        else:
            flash('Correo ya existe.')
            return render_template('register.html')

@app.route('/login', methods=['POST','GET'])
def login():
    error = None
    if request.method == 'POST':
        session.pop('user', None)
        contraseña = request.form['password']
        result = ""
        users = mongo.db.users
        email = users.find_one({'email' : request.form['email']})
        contraseña = request.form['password']

        if email:
            password = email['password']
            if bcrypt.check_password_hash(password, contraseña):
                access_token = create_access_token(identity={
                    'name': email['name'],
                    'last_name': email['last_name'],
                    'email': email['email'],
                })
                
                session['user'] = request.form['email']

                return redirect(url_for('index'))
            else:
                result = "Usuario y/o contraseña invalido"
            

                return render_template('login.html', result=result)
        else:
            result =  "Usuario no registrado"

            return render_template('login.html', result=result)

@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']

@app.route('/protegido')
def protegido():
    if g.user:
        return render_template('index.html')
    return redirect(url_for('login_access'))

@app.route('/salir')
def salir():
    session.pop('user', None)
    flash('Cerro sesión')
    return redirect(url_for('login_access'))


if __name__=="__main__":
    app.run(debug=True)