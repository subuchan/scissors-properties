from app.model_controller.auth_model import User
from app.utils import generate_username, generate_password
from bson import ObjectId
from werkzeug.security import generate_password_hash
import random
from datetime import datetime,timedelta

class AuthService:
    def __init__(self, db): 
        self.auth_model = User(db)

    def signup(self, data):
        if self.auth_model.find_by_email(data.email):
            return None, "User with this email already exists"
        if self.auth_model.find_by_mobile(data.mobile_number):
            return None, "User with this mobile number already exists"

        user_id = self.auth_model.create_user(data.user_name, data.mobile_number, data.email)
        user = self.auth_model.find_by_id(user_id)
        return user, None

    def signin(self, data):
        user = self.auth_model.find_by_username(data.login_input) \
            or self.auth_model.find_by_email(data.login_input) \
            or self.auth_model.find_by_mobile(data.login_input)

        if not user:
            return None, "User not found"

        if not user.get('password'):
            return None, "Password not set. Please contact support"

        if not self.auth_model.check_password(user['password'], data.password):
            return None, "Incorrect password"

        return str(user['_id']), None

    def generate_username_password(self, user_name, mobile_number):
        username = generate_username(user_name, mobile_number)
        password = generate_password()
        return username, password

    def complete_payment(self, user_id):
        user = self.auth_model.find_by_id(user_id)
        if not user:
            return None, "User not found"

        if user.get('is_paid'):
            return None, "Payment already completed"

        username, password = self.generate_username_password(user['user_name'], user['mobile_number'])
        self.auth_model.set_password(user_id, password)
        self.auth_model.update({'_id': user['_id']}, {
            'username': username,
            'is_paid': True
        })

        return (username, password), None

    def user_change_password(self, user_id, data):
        if data.new_password != data.confirm_password:
            return False, "Passwords do not match"

        hashed_password = generate_password_hash(data.new_password)
        result = self.auth_model.update_password(
            {"_id": ObjectId(user_id)},
            {
                "password": hashed_password,
                "passwordChanged": True
            }
        )
        if result.modified_count == 0:
            return False, "User not found or password not updated"
        return True, None


    def find_by_email(self, email):
        return self.auth_model.find_one({'email': email})

    def update_password(self, email, new_password):
        hashed = hash_password(new_password)  # Use your password hashing function here
        result = self.auth_model.update({'email': email}, {'password': hashed})
        if result.modified_count == 1:
            return True, None
        return False, "Update failed"

    def store_otp(self, email, otp):
        update_data = {'otp': otp} if otp else {'$unset': {'otp': ""}}
        update_data['updatedAt'] = datetime.utcnow()
        return self.auth_model.update_one({'email': email}, {'$set': update_data})

    def find_user_by_email(self, email):
        return self.auth_model.find_by_email(email)

    def generate_otp(self, length=6):
        return ''.join(str(random.randint(0, 9)) for _ in range(length))

    def send_otp_email(self, email, otp):
        # Replace with your actual email sending logic
        try:
            print(f"Sending OTP {otp} to {email}")  # Stub print
            return True, None
        except Exception as e:
            return False, str(e)

    def store_otp(self, email, otp):
        return self.auth_model.store_otp(email, otp)

    def verify_otp(self, user, otp, expiry_minutes=15):
        if not user.get('otp') or not user.get('otp_created_at'):
            return False
        if user['otp'] != otp:
            return False
        otp_age = datetime.utcnow() - user['otp_created_at']
        if otp_age > timedelta(minutes=expiry_minutes):
            return False
        return True

    def update_password(self, email, new_password):
        return self.auth_model.update_password(email, new_password)

    def find_user_by_otp(self, otp):
        return self.auth_model.find_by_otp(otp)

    def verify_otp(self, user, otp, expiry_minutes=15):
        if not user.get('otp') or not user.get('otp_created_at'):
            return False
        if user['otp'] != otp:
            return False
        otp_age = datetime.utcnow() - user['otp_created_at']
        if otp_age > timedelta(minutes=expiry_minutes):
            return False
        return True

    def update_password(self, user_id, new_password):
        return self.auth_model.update_password(user_id, new_password)

    def store_otp(self, user_id, otp):
        return self.auth_model.store_otp(user_id, otp)

    def get_all_requests(self):
        return self.auth_model.get_pending_requests()

    