from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
from config import Config
from flask_mail import Mail
from flask_cors import CORS

bcrypt = Bcrypt()
jwt = JWTManager()
mail = Mail()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    bcrypt.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    CORS(app)


    client = MongoClient(app.config['MONGO_URI'])
    app.db = client.get_default_database()

    from app.route_controller.auth_route import auth_bp
    from app.route_controller.admin_route import admin_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp,url_prefix='/admin')


    return app
