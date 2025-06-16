from flask import request, current_app, jsonify, render_template
from flask_mail import Message
from flask_jwt_extended import verify_jwt_in_request
from functools import wraps
from app import mail
from bson import ObjectId
from datetime import datetime 
import re
import random
import string

# -------------------------------
# JWT Token Validator Decorator
# -------------------------------
def token_required(fn):
    @wraps(fn)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization', None)
        if not token:
            return jsonify({"message": "Token is missing", "status_code": 401}), 401

        try:
            token = token.split(' ')[1]
            verify_jwt_in_request()

            if not is_token_valid_in_mongodb(token):
                return jsonify({"message": "Token is invalid or expired", "status_code": 401}), 401

            return fn(*args, **kwargs)

        except Exception as e:
            print(str(e))
            return jsonify({"message": "Error validating token", "status_code": 401}), 401

    return decorator


def is_token_valid_in_mongodb(token):
    token_doc = current_app.db.userSessions.find_one({"token": token, "loggedIn": True})
    return token_doc is not None


# -------------------------------
# JSON API Standard Response
# -------------------------------
def response_with_code(status_code, message, data=None):
    return jsonify({
        "status_code": status_code,
        "message": message,
        "data": data
    }), status_code


# -------------------------------
# Password, OTP, and Username Utils
# -------------------------------
def generate_password(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_username(user_name, mobile_number):
    return f"{user_name[:4].lower()}{str(mobile_number)[-4:]}"

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def validate_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password)
    )


# -------------------------------
# Email Utility Functions
# -------------------------------
# def send_email(subject, recipients, html_body):
#     try:
#         msg = Message(subject, recipients=recipients)
#         msg.html = html_body
#         mail.send(msg)
#     except Exception as e:
#         print(f"Failed to send email: {e}")
def send_email(subject, recipients, html_body):
    try:
        # Ensure recipients is a list of valid email strings
        if isinstance(recipients, str):
            recipients = [recipients]  # Wrap single email string in list
        elif isinstance(recipients, list):
            # Ensure all elements are full email strings, not characters
            recipients = [r for r in recipients if isinstance(r, str) and '@' in r]
        else:
            raise TypeError("Recipients must be a string or a list of email strings")

        if not recipients:
            raise ValueError("No valid email recipients found.")

        msg = Message(subject, recipients=recipients)
        msg.html = html_body
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")



def send_otp_email(receiver_email, otp):
    try:
        subject = "OTP for Password Reset"
        html_body = render_template('otp_email.html', otp=otp)

        msg = Message(subject, recipients=[receiver_email])
        msg.html = html_body
        mail.send(msg)
        print(f"OTP email sent to {receiver_email}")
        return True, None
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        return False, str(e)


def send_welcome_email(user_name, to_email):
    html = render_template('welcome_email.html', user_name=user_name)
    send_email('Welcome to Platform', [to_email], html)


def send_credentials_email(username, password, to_email):
    html = render_template('send_credentials.html', username=username, password=password)
    send_email('Your Login Credentials', [to_email], html)


def send_admin_notification_email(user):
    subject = "New Payment Confirmation - Awaiting Approval"

    html_body = f"""
    <html>
      <body>
        <p>A new user has completed payment.</p>
        <p><strong>Name:</strong> {user.get('user_name', 'N/A')}</p>
        <p><strong>Email:</strong> {user.get('email', 'N/A')}</p>
        <p><strong>Mobile:</strong> {user.get('mobile_number', 'N/A')}</p>
        <br />
        <p>
          🔀 <a href=\"https://scissorsproperties.com/admin-login\" target=\"_blank\">
          Click here to approve or decline
          </a>
        </p>
      </body>
    </html>
    """

    plain_body = f"""
    A new user has completed payment.

    Name: {user.get('user_name', 'N/A')}
    Email: {user.get('email', 'N/A')}
    Mobile: {user.get('mobile_number', 'N/A')}

    Click to approve or decline:
    http://localhost:3000/admin-login
    """

    msg = Message(subject, recipients=["santhana7999@gmail.com"], body=plain_body)
    msg.html = html_body
    mail.send(msg)


# -------------------------------
# BSON / MongoDB Helpers
# -------------------------------
def convert_objectid_to_str(data):
    if isinstance(data, list):
        for doc in data:
            if '_id' in doc:
                doc['_id'] = str(doc['_id'])
            if 'createdAt' in doc:
                doc['createdAt'] = doc['createdAt'].isoformat()
            if 'updatedAt' in doc:
                doc['updatedAt'] = doc['updatedAt'].isoformat()
        return data
    elif isinstance(data, dict):
        if '_id' in data:
            data['_id'] = str(data['_id'])
        if 'createdAt' in data:
            data['createdAt'] = data['createdAt'].isoformat()
        if 'updatedAt' in data:
            data['updatedAt'] = data['updatedAt'].isoformat()
        return data
    return data
