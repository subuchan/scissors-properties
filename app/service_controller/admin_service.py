from app.model_controller.admin_model import Admin
from app.utils import validate_password,generate_otp,send_credentials_email,response_with_code,send_email
import random
from datetime import datetime,timedelta
from bson import ObjectId
from app.model_controller.auth_model import User
import string
from flask import render_template
from werkzeug.security import generate_password_hash, check_password_hash


class AdminService:
    def __init__(self, db):
        self.admin_model = Admin(db)
        self.auth_model=User(db)


    def register_user(self,data):
        try:
            if not validate_password(data.password):
                return True, "Provided password does not meet requirements"

            if self.admin_model.find_by_email(data.email):
                return None, "User already exists"

            admin_id = self.admin_model.create_admin_user(data)
            return admin_id, None

        except Exception as e:
            return None, str(e)
        
    def Admin(self,email, password):
        admin = self.admin_model.find_by_email(email)
        if admin and self.admin_model.check_password(admin['password'], password):
            return admin, None
        if not admin: 
            return False,"user not found"
        if not self.admin_model.check_password(admin['password'], password):
            return False,"password is Incorrect"

    # def get_all_requests(self):
    #     return self.admin_model.get_pending_requests()

    def handle_request(self, user_id, action):
        if action not in ['Accepted', 'Ignored']:
            return None, "Invalid action"

        result = self.admin_model.update_request_status(ObjectId(user_id), action)
        if result.modified_count == 0:
            return None, "No document updated"
        return True, None

    def change_password(self, admin_id, data):
        admin = self.admin_model.find_by_admin_id(admin_id)
        if not admin:
            return None, "Admin not found"

        if not self.admin_model.check_password(admin['password'], data.old_password):
            return None, "Old password is incorrect"

        if data.new_password != data.confirm_password:
            return None, "New passwords do not match"

        if not validate_password(data.new_password):
            return None, "Password does not meet requirements"

        updated = self.admin_model.update_password(admin_id, data.new_password)
        return updated, None

    def forgot_password(self, admin_id, email):
        admin = self.admin_model.find_by_admin_id(admin_id)
        if not admin or admin.get('email') != email:
            return None, "Admin not found or email mismatch"

        otp = generate_otp()
        self.admin_model.store_otp(admin_id, otp)
        send_otp_email(email, otp)
        return otp, None

    # def reset_password(self, admin_id, otp, new_password, confirm_password):
    #     admin = self.admin_model.find_by_admin_id(admin_id)
    #     if not admin:
    #         return None, "Admin not found"

    #     if new_password != confirm_password:
    #         return None, "Passwords do not match"

    #     stored_otp = admin.get("otp")
    #     if not stored_otp or stored_otp != otp:
    #         return None, "Invalid or expired OTP"

    #     if not validate_password(new_password):
    #         return None, "Password does not meet requirements"

    #     self.admin_model.update_password(admin_id, new_password)
    #     self.admin_model.clear_otp(admin_id)
    #     return True, None

    def find_admin_by_email(self, email):
        return self.admin_model.find_by_email(email)

    def store_otp(self, email, otp):
        update_data = {'otp': otp} if otp else {'$unset': {'otp': ""}}
        update_data['updatedAt'] = datetime.utcnow()
        return self.admin_model.update_one({'email': email}, {'$set': update_data})

    def generate_otp(self, length=6):
        return ''.join(str(random.randint(0, 9)) for _ in range(length))

    def update_password(self, email, new_password):
        return self.admin_model.update_password(email, new_password)

    def find_user_by_otp(self, otp):
        return self.admin_model.find_by_otp(otp)

    def verify_otp(self, admin, otp, expiry_minutes=15):
        if not admin.get('otp') or not admin.get('otp_created_at'):
            return False
        if admin['otp'] != otp:
            return False
        otp_age = datetime.utcnow() - admin['otp_created_at']
        if otp_age > timedelta(minutes=expiry_minutes):
            return False
        return True

    def update_password(self, user_id, new_password):
        return self.admin_model.update_password(user_id, new_password)

    def store_otp(self, user_id, otp):
        return self.admin_model.store_otp(user_id, otp)
    
    def get_pending_users(self):
        users = self.auth_model.get_pending_requests()
        return response_with_code(200, "Pending users fetched", users)

    def approve_user(self, user_id):
        user = self.auth_model.find_user_by_id(user_id)
        if not user:
            return response_with_code(404, "User not found")

        name_part = user.get("user_name", "User")[:4].capitalize()
        mobile_part = str(user.get("mobile_number", "0000000000"))[-4:]
        username = f"{name_part}{mobile_part}"

        # Generate plain and hashed password
        provided_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        hashed_password = generate_password_hash(provided_password)

        # Update DB
        update_result = self.auth_model.update_user_status_accepted(
            user_id, username, hashed_password
        )
        if not update_result:
            return response_with_code(500, "Failed to update user")

        # Send email
        html = render_template('send_credentials.html', username=username, password=provided_password)
        send_email(
            subject="Your Login Credentials",
            recipients=user['email'],
            html_body=html
        )

        return response_with_code(200, "User approved and credentials sent")




    def decline_user(self, user_id):
        user = self.auth_model.find_user_by_id(user_id)
        if not user:
            return response_with_code(404, "User not found")

        self.auth_model.update_user_status_declined(user_id)

        html_body = render_template('decline_email.html', user_name=user.get("user_name", "User"),admin_email="admin@example.com")

        send_email(
            subject="Registration Declined",
            recipients=[user['email']],
            html_body=html_body
        )

        return response_with_code(200, "User declined and notified")