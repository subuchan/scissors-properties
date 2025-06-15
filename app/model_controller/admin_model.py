from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from datetime import datetime
from app.utils import convert_objectid_to_str

class Admin:
    def __init__(self, db):
        self.admin = db.admin

    def create_admin_user(self, data):
        password_hash=generate_password_hash(data.password, method='pbkdf2:sha512') 
        now = datetime.utcnow()
        admin_data = {
            'email': data.email,
            'mobileNumber': data.mobileNumber,
            'adminId': data.adminId,
            'createdAt': now,
            'updatedAt': now,
            'password':password_hash
        }
        result = self.admin.insert_one(admin_data)
        return result.inserted_id
    
    def find_by_email(self, email):
        admin = self.admin.find_one({'email': email})
        if admin:
            admin['_id'] = str(admin['_id']) 
        return admin
    
    @staticmethod
    def check_password(stored_password, provided_password):
        return check_password_hash(stored_password, provided_password)

    def find_by_id(self, adminId):
        result = self.admin.find_one({'adminId': adminId})
        return  result

    def find_by_admin_id(self, adminId):
        result = self.admin.find_one({'_id':ObjectId(adminId)})
        return  result

    def update_password(self, admin_id, new_password):
        hashed = generate_password_hash(new_password, method='pbkdf2:sha512')
        result = self.admin.update_one(
            {'_id':ObjectId(admin_id)},
            {'$set': {'password': hashed, 'updatedAt': datetime.utcnow()}}
        )
        return result.modified_count > 0

    def store_otp(self, admin_id, otp):
        self.admin.update_one(
            {'_id': ObjectId(admin_id)},
            {'$set': {'otp': otp, 'otp_created_at': datetime.utcnow()}}
        )

    def clear_otp(self, admin_id):
        self.admin.update_one(
            {'_id':ObjectId(admin_id)},
            {'$unset': {'otp': "", 'otp_created_at': ""}}
        )
    
    def find_by_email(self, email):
        return self.admin.find_one({'email': email})

    def update_one(self, filter_dict, update_dict):
        update_dict['updatedAt'] = datetime.utcnow()
        return self.admin.update_one(filter_dict, {'$set': update_dict})

    def find_by_otp(self, otp):
        # OTP must be unique or assume first found user with OTP
        return self.admin.find_one({"otp": otp})


    # def get_pending_requests(self):
    #     cursor = self.admin.find({"status": {"$in": ["Pending", None]}})
    #     return convert_objectid_to_str(list(cursor))


    # def update_request_status(self, user_id, status):
    #     return self.admin.update_one(
    #         {"_id":ObjectId(user_id)},
    #         {"$set": {"status": status}}
    #     )