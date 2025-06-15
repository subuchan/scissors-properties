from flask import request, current_app, jsonify
from app.service_controller.admin_service import AdminService
from app.service_controller.auth_service import AuthService
from pydantic import BaseModel, EmailStr, ValidationError, constr
from app.utils import response_with_code, generate_otp, send_otp_email, send_email
from bson.objectid import ObjectId

# ---------------------------
# ✅ Pydantic Schemas
# ---------------------------
class AdminSchema(BaseModel):
    email: EmailStr
    adminId: str
    password: str
    mobileNumber: int

class LoginSchema(BaseModel):
    email: str
    password: str

class ChangePasswordSchema(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str

class ForgotPasswordSchema(BaseModel):
    email: EmailStr

class ResetPasswordSchema(BaseModel):
    otp: constr(min_length=6, max_length=6)
    new_password: str
    confirm_password: str

class HandleRequestSchema(BaseModel):
    userId: str
    action: str


# ---------------------------
# ✅ Admin API Controllers
# ---------------------------

def admin_create():
    try:
        data = AdminSchema(**request.get_json())
    except ValidationError as e:
        return response_with_code(400, "Validation error", e.errors())

    admin_service = AdminService(current_app.db)
    admin_id, error = admin_service.register_user(data)
    if error:
        return response_with_code(400, error)

    return response_with_code(200, "Admin created successfully")


def admin_login():
    try:
        data = LoginSchema(**request.get_json())
    except ValidationError as e:
        return response_with_code(400, "Validation error", e.errors())

    admin_service = AdminService(current_app.db)
    admin, error = admin_service.Admin(data.email, data.password)

    if error:
        return response_with_code(401, "Invalid email or password")

    return response_with_code(200, "Admin Logged in Successfully", {"email": admin["email"]})


def change_password():
    try:
        data = ChangePasswordSchema(**request.get_json())
        admin_id = request.args.get("_id")
        if not admin_id:
            return response_with_code(400, "Missing adminId in query parameter")
    except ValidationError as e:
        return response_with_code(400, "Validation error", e.errors())

    admin_service = AdminService(current_app.db)
    result, error = admin_service.change_password(admin_id, data)
    if error:
        return response_with_code(400, error)

    return response_with_code(200, "Password changed successfully")


def forgot_password():
    try:
        data = ForgotPasswordSchema(**request.get_json())
    except ValidationError as e:
        return response_with_code(400, "Validation error", e.errors())

    admin_service = AdminService(current_app.db)
    admin = admin_service.find_admin_by_email(data.email)
    if not admin:
        return response_with_code(400, "Admin not found")

    otp = generate_otp()
    print(f"Sending OTP {otp} to {data.email}")

    success, err = send_otp_email(data.email, otp)
    if not success:
        return response_with_code(500, "Failed to send OTP", err)

    admin_service.store_otp(admin['_id'], otp)
    return response_with_code(200, "OTP sent successfully")


def reset_password():
    try:
        data = ResetPasswordSchema(**request.get_json())
    except ValidationError as e:
        return response_with_code(400, "Validation error", e.errors())

    if data.new_password != data.confirm_password:
        return response_with_code(400, "Passwords do not match")

    admin_service = AdminService(current_app.db)
    admin = admin_service.find_user_by_otp(data.otp)
    if not admin or not admin_service.verify_otp(admin, data.otp):
        return response_with_code(400, "Invalid or expired OTP")

    success = admin_service.update_password(admin['_id'], data.new_password)
    if not success:
        return response_with_code(500, "Failed to update password")

    admin_service.store_otp(admin['_id'], None)  # Clear OTP after reset
    return response_with_code(200, "Password reset successful")


# ---------------------------
# ✅ User Approval / Requests
# ---------------------------

def get_pending_users():
    users = list(current_app.db.users.find({'status': 'Pending'}))
    for user in users:
        user['_id'] = str(user['_id'])
    return response_with_code(200, "Pending users fetched", users)


def approve_user(user_id):
    auth_service = AuthService(current_app.db)
    creds, error = auth_service.approve_user(user_id)
    if error:
        return response_with_code(400, error)

    user = current_app.db.users.find_one({'_id': ObjectId(user_id)})
    send_email("Account Approved", f"Your login credentials:\nUsername: {creds[0]}\nPassword: {creds[1]}", [user['email']])
    return response_with_code(200, "User approved and credentials sent")


def decline_user(user_id):
    current_app.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'status': 'Declined'}})

    user = current_app.db.users.find_one({'_id': ObjectId(user_id)})
    send_email("Registration Declined", "Your registration has been declined. Please contact admin.", [user['email']])

    return response_with_code(200, "User declined and notified")


def get_all_login_requests():
    admin_service = AdminService(current_app.db)
    return admin_service.get_pending_users()


def handle_login_request():
    try:
        data = HandleRequestSchema(**request.get_json())

        admin_service = AdminService(current_app.db)

        if data.action == "Accepted":
            return admin_service.approve_user(data.userId)
        elif data.action == "Ignored":
            return admin_service.decline_user(data.userId)
        else:
            return response_with_code(400, "Invalid action type")

    except ValidationError as e:
        return response_with_code(400, "Validation error", e.errors())
    except Exception as e:
        return response_with_code(500, f"Internal server error: {str(e)}")
