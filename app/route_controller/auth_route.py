from flask import Blueprint
from app.auth_controller.auth import (
    Signup, Login, Forgot_password, Change_password,Reset_password,
    Payment_page, Payment_qr, Complete_payment,
)

auth_bp = Blueprint('auth_bp', __name__)

auth_bp.route('/register', methods=['POST'])(Signup)
auth_bp.route('/login', methods=['POST'])(Login)
auth_bp.route('/forgot-password', methods=['POST'])(Forgot_password)
auth_bp.route('/reset-password', methods=['POST'])(Reset_password)
auth_bp.route('/change-password', methods=['POST'])(Change_password)

auth_bp.route('/payment/<user_id>', methods=['GET'])(Payment_page)
auth_bp.route('/payment_qr/<user_id>', methods=['GET'])(Payment_qr)
auth_bp.route('/complete_payment', methods=['GET'])(Complete_payment)
