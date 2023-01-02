from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import json 



#-------------------------------------------web3 connection-----------------------------------------
import json
from web3 import Web3

ganache_url="http://127.0.0.1:7545"
web3=Web3(Web3.HTTPProvider(ganache_url))
#0x0D741328f73894EAC1531424041533906F65FD55
#abi=json.loads('[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"string","name":"_nombrePersona","type":"string"},{"internalType":"uint256","name":"_edadPersona","type":"uint256"},{"internalType":"string","name":"_idPersona","type":"string"}],"name":"Representar","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"VerResultado","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_candidato","type":"string"}],"name":"VerVotos","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_candidato","type":"string"}],"name":"Votar","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"_mail","type":"string"},{"internalType":"string","name":"_pass","type":"string"}],"name":"login","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"verCAndidatos","outputs":[{"internalType":"string[]","name":"","type":"string[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_mail","type":"string"},{"internalType":"string","name":"_pass","type":"string"}],"name":"verifi","outputs":[],"stateMutability":"nonpayable","type":"function"}]')
abi=json.loads('[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"string","name":"_nombre","type":"string"},{"internalType":"string","name":"_apellido","type":"string"},{"internalType":"string","name":"_mail","type":"string"},{"internalType":"string","name":"_contrasenia","type":"string"}],"name":"agregarUsuario","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_mail","type":"string"}],"name":"verCAndidatos","outputs":[{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"},{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"}]')


#var loginContract = new web3.eth.Contract([{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"imprimir","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_mail","type":"string"},{"internalType":"string","name":"_pass","type":"string"}],"name":"log","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_mail","type":"string"},{"internalType":"string","name":"_pass","type":"string"}],"name":"verifi","outputs":[],"stateMutability":"nonpayable","type":"function"}]);
#direccion del contraro deployed
address=web3.toChecksumAddress("0xda622f5E5250e3c4Dbbf7D933548f2897Fa9AA03")
#var votacionContract = new web3.eth.Contract([{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"string","name":"_nombrePersona","type":"string"},{"internalType":"uint256","name":"_edadPersona","type":"uint256"},{"internalType":"string","name":"_idPersona","type":"string"}],"name":"Representar","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"VerResultado","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_candidato","type":"string"}],"name":"VerVotos","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_candidato","type":"string"}],"name":"Votar","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"_mail","type":"string"},{"internalType":"string","name":"_pass","type":"string"}],"name":"login","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"verCAndidatos","outputs":[{"internalType":"string[]","name":"","type":"string[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_mail","type":"string"},{"internalType":"string","name":"_pass","type":"string"}],"name":"verifi","outputs":[],"stateMutability":"nonpayable","type":"function"}]);
contract=web3.eth.contract(address=address,abi=abi)
#------------------------------------------------------------------------------------------------------
class User1():
    #id = db.Column(db.Integer, primary_key=True)
    email =""
    password =""
    first_name =""
    last_name =""
    #notes = db.relationship('Note')


auth = Blueprint('auth', __name__)

web3=Web3(Web3.HTTPProvider(ganache_url))
#-----------x-------------------------------
web3.eth.defaultAccount=web3.eth.accounts[0]

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        #contract.functions.log(email,password).call()
        #txHash=contract.functions.log(email,password).transact({'from': web3.eth.accounts[0], 'gasPrice': web3.eth.gasPrice, 'gas': web3.eth.getBlock('latest').gasLimit})
        #print(txHash)
#chekeo en la base 
        
        #contract.functions.verCAndidatos(email).call()
        
        list=[]
        list=contract.functions.verCAndidatos(email).call() #verCAndidatos
        print(list)
        print("here")
        user=User1() 
        user.first_name=list[0]
        user.email=list[1]
        user.last_name=list[2]
        user.password=list[3]
        print(user.password)
        print(list[3])
        #user = User.query.filter_by(email=email).first()
        if list[3]:
            if (list[3]== password):
                print(list[3],password)
                flash('Logged in successfully!', category='success')
                #login_user(user, remember=True)
                #return redirect(url_for('views.home'))
                return render_template("home.html", user=current_user)
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
#
    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/table')
#@login_required
def table():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

    #logout_user()
    return redirect(url_for('auth.login'))
##---added
@auth.route('/register', methods=['GET', 'POST'])
def reg_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        password1="paass"
        password1 = request.form.get('password')
        password2 = request.form.get('password_repeat')
        contract.functions.agregarUsuario(first_name,first_name,email,password1).transact({'from': web3.eth.accounts[0], 'gasPrice': web3.eth.gasPrice, 'gas': web3.eth.getBlock('latest').gasLimit})
        flash('Account created!', category='success')
    return render_template("register.html", user=current_user)
##----


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
    #------------------consulta el usuario
        #contract.functions.log(email,password).transact({'from': web3.eth.accounts[0], 'gasPrice': web3.eth.gasPrice, 'gas': web3.eth.getBlock('latest').gasLimit})

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 5:
            flash('Password must be at least 7 characters.', category='error')
        else:
            #new_user = User(email=email, first_name=first_name, password=generate_password_hash(
             #   password1, method='sha256'))
            #metodo de guardado de usuario crado
            contract.functions.agregarUsuario(first_name,first_name,email,password1).transact({'from': web3.eth.accounts[0], 'gasPrice': web3.eth.gasPrice, 'gas': web3.eth.getBlock('latest').gasLimit})
    
            #-----guardado en base------
            #db.session.add(new_user)
            #db.session.commit()
            
            #login_user(new_user, remember=True)
            #
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
