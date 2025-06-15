from datetime import datetime
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from app.utils import convert_objectid_to_str

class User:
    def __init__(self, db):
        self.users = db.users

    def create_user(self, user_name, mobile_number, email):
        now = datetime.utcnow()
        result = self.users.insert_one({
            'user_name': user_name,
            'mobile_number': mobile_number,
            'email': email,
            'password': None,
            'username': None,
            'IsEmailVerified': False,
            'createdAt': now,
            'updatedAt': now,
            'status': "Pending"
        })
        return str(result.inserted_id)


    def find_by_email(self, email):
        return self.users.find_one({'email': email})

    def find_by_id(self, user_id):
        return self.users.find_one({'_id': ObjectId(user_id)})

    def find_by_username(self, username):
        return self.users.find_one({'username': username})

    def find_by_mobile(self, mobile_number):
        return self.users.find_one({'mobile_number': mobile_number})

    def update(self, filter_dict, update_dict):
        update_dict['updatedAt'] = datetime.utcnow()
        return self.users.update_one(filter_dict, {'$set': update_dict})

    def check_password(self, stored_password, provided_password):
        return check_password_hash(stored_password, provided_password)

    def set_password(self, user_id, password):
        hashed_password = generate_password_hash(password)
        return self.update({'_id': ObjectId(user_id)}, {'password': hashed_password})

    def store_otp(self, user_id, otp):
        if otp:
            update_data = {'otp': otp, 'otp_created_at': datetime.utcnow()}
            result = self.users.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
        else:
            result = self.users.update_one({'_id': ObjectId(user_id)}, {'$unset': {'otp': "", 'otp_created_at': ""}})
        return result.modified_count == 1

    def find_by_otp(self, otp):
        return self.users.find_one({"otp": otp})

    def update_password(self, user_id, new_password):
        hashed = generate_password_hash(new_password)
        result = self.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'password': hashed,
                'updatedAt': datetime.utcnow()
            }}
        )
        return result.modified_count == 1




    def get_pending_requests(self):
        # status can be either not set or explicitly marked as "Pending"
        users = list(self.users.find({"status": {"$in": [None, "", "Pending"]}}))
        return convert_objectid_to_str(users)

    def update_user_status_accepted(self, user_id, username, hashed_password):
        result = self.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'status': 'Accepted',
                'username': username,
                'password': hashed_password,  # already hashed!
                'updatedAt': datetime.utcnow()
            }}
        )
        return result.modified_count > 0


    def update_user_status_declined(self, user_id):
        result = self.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'status': 'Declined',
                'updatedAt': datetime.utcnow()
            }}
        )
        return result.modified_count > 0

    def find_user_by_id(self, user_id):
        return self.users.find_one({'_id': ObjectId(user_id)})
