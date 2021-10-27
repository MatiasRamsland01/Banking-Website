import decimal
import os


from flask import Flask, flash
from flask_sqlalchemy import SQLAlchemy
from website import db
from flask_login import UserMixin
from sqlalchemy import or_
from sqlalchemy.sql.expression import null
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base



    





encKey = b'FtSL3pqkp2yHZIDPCmP3e_70WJX2GK2iFpEtPcx7MAk='
Encrypter = Fernet(encKey)

def EncryptMsg(string):
    try:
        encoded = string.encode()
        encMsg = Encrypter.encrypt(encoded)
    except AttributeError:
        nyString = str(string)
        nyEncoded = nyString.encode()
        encMsg = Encrypter.encrypt(nyEncoded)
    return encMsg

def DecryptMsg(encString):
    decMsg = Encrypter.decrypt(encString)
    decoded = decMsg.decode()
    return decoded

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=False, nullable=False)
    token = db.Column(db.Text, nullable=False)
    FA = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        # Create hashed password
        self.password = generate_password_hash(
            password,
            method='sha256'
        )

    def check_password(self, password):
        # return check_password_hash(self.password, password)
        if self.password == password:
            return True


    def get_money(self):
        return get_money_from_user(self.username)


class Transaction(UserMixin, db.Model):
    transaction_id = db.Column(db.Integer, primary_key=True)
    # Out Id & Money can be null because we might put in (or take out) money through an ATM
    from_user_id = db.Column(db.Integer, nullable=True)  # TODO ForeignKey?
    out_money = db.Column(db.String(40), nullable=True)
    to_user_id = db.Column(db.Integer)  # TODO ForeignKey?
    in_money = db.Column(db.String(40))
    message = db.Column(db.String(120))

    # TimeStamp?

     

    def contains_user(self, username):
        return username != "" and (self.from_user_id == username or self.to_user_id == username)

    def get_out_money_decimal(self):
        if self.out_money is None:
            return 0
        return decimal.Decimal(DecryptMsg(self.out_money))

    def get_in_money_decimal(self):
        if self.in_money is None:
            return 0
        return decimal.Decimal(DecryptMsg(self.in_money))   

    def __eq__(self, other):
        return self.transaction_id == other.transaction_id


def get_money_from_user(username):
    money = 0
    transactionstext = []
    user = User.query.filter_by(username=username).first()
    if not user:
        print(f"Couldn't find user with username {username}")
        return money

    transactions = Transaction.query.filter(    
        or_(Transaction.from_user_id == username, Transaction.to_user_id == username))
    for transaction in transactions:
        # If from_user_id; substract money
        if transaction.from_user_id and transaction.from_user_id == username:
            transactionstext.append(f"Out Money: {transaction.to_user_id} --> {transaction.from_user_id}: - {transaction.get_out_money_decimal()}kr. Message: {transaction.message} \n")
            money -= transaction.get_out_money_decimal()
        # If to_user_id; add money
        elif transaction.to_user_id and transaction.to_user_id == username:
            if transaction.from_user_id == None:
                transactionstext.append(f"In Money: ATM deposit --> {transaction.to_user_id}: + {transaction.get_in_money_decimal()}kr. \n")
            else:
                transactionstext.append(f"In Money: {transaction.from_user_id} --> {transaction.to_user_id}: + {transaction.get_in_money_decimal()}kr. Message: {transaction.message} \n")
            money += transaction.get_in_money_decimal()

    return money, transactionstext





