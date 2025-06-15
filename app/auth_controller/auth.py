from flask import request, jsonify, current_app, send_file
from pydantic import BaseModel, EmailStr, ValidationError,constr
from flask_jwt_extended import get_jwt_identity
from bson import ObjectId
import qrcode
import io
from app.service_controller.auth_service import AuthService
from app.utils import send_welcome_email,send_admin_notification_email,send_credentials_email, generate_otp, send_otp_email, response_with_code


class RegisterSchema(BaseModel):
    user_name: str
    mobile_number:int
    email: EmailStr

class LoginSchema(BaseModel):
    login_input: str
    password: str

class ChangePasswordSchema(BaseModel):
    new_password: str
    confirm_password: str

class ForgotPasswordSchema(BaseModel):
    email: EmailStr


class ResetPasswordSchema(BaseModel):
    otp: constr(min_length=6, max_length=6)
    new_password:str
    confirm_password:str

def Signup():
    try:
        data = RegisterSchema(**request.get_json())
    except ValidationError as e:
        return response_with_code(400, "Validation error", e.errors())

    auth_service = AuthService(current_app.db)
    user, error = auth_service.signup(data)
    if error:
        return response_with_code(400, error)

    current_app.db.users.update_one(
        {"_id": ObjectId(user['_id'])},
        {"$set": {"isEmailVerified": True}}
    )
    send_welcome_email(data.user_name, [data.email])
    return response_with_code(200, "User registered successfully", str(user['_id']))

def Payment_page(user_id):
    auth_service = AuthService(current_app.db)
    user = auth_service.auth_model.find_by_id(user_id)
    if not user:
        return response_with_code(404, "User not found")

    html = f"""
    <h2>Pay ₹4999 to complete registration</h2>
    <img src="/auth/payment_qr/{user_id}" alt="Payment QR Code" />
    <p>After payment, <a href="/auth/complete_payment?user_id={user_id}">Click here to confirm payment</a></p>
    """
    return html

def Payment_qr(user_id):
    payment_url = "upi://pay?pa=merchant@upi&pn=Scissors&am=4999"
    qr_img = qrcode.make(payment_url)
    buf = io.BytesIO()
    qr_img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

def Complete_payment():
    user_id = request.args.get('user_id')
    if not user_id:
        return response_with_code(400, "Missing user_id")

    auth_service = AuthService(current_app.db)
    user = auth_service.auth_model.find_by_id(user_id)

    if not user:
        return response_with_code(404, "User not found")

    # ✅ Step 1: Update status to "Pending"
    current_app.db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"status": "Pending"}}
    )

    # ✅ Step 2: Send email to admin with user details
    send_admin_notification_email(user)

    # ✅ Respond to frontend
    return response_with_code(200, "Payment completed. Awaiting admin approval.")

def Login():
    try:
        data = LoginSchema(**request.get_json())
    except ValidationError as e:
        return jsonify({
            "status_code": 400,
            "message": "Validation error",
            "data": e.errors()
        }), 400

    auth_service = AuthService(current_app.db)
    user_id, error = auth_service.signin(data)
    if error:
        return jsonify({"status_code": 400, "message": error}), 400

    return jsonify({
        "status_code": 200,
        "message": "User login successfully",
        "data": {
            "user_id": user_id
        }
    })

def Change_password():
    try:
        data = ChangePasswordSchema(**request.get_json())
    except ValidationError as e:
        return response_with_code(400, "Validation error", e.errors())

    user_id = request.args.get("user_id")
    if not user_id:
        return response_with_code(400, "Missing user_id in query parameters")
    try:
        object_id = ObjectId(user_id)
    except Exception:
        return response_with_code(400, "Invalid user_id format")
    auth_service = AuthService(current_app.db)
    success, error = auth_service.user_change_password(user_id, data)
    if error:
        return response_with_code(400, error)

    return response_with_code(200, "Password changed successfully")

def Forgot_password():
    try:
        data = ForgotPasswordSchema(**request.get_json())
    except ValidationError as e:
        return response_with_code(400, "Validation error", e.errors())

    auth_service = AuthService(current_app.db)
    user = auth_service.find_user_by_email(data.email)
    if not user:
        return response_with_code(400, "User not found")

    otp = auth_service.generate_otp()
    print(f"Sending OTP {otp} to {data.email}")

    success, err = send_otp_email(data.email, otp)
    if not success:
        return response_with_code(500, "Failed to send OTP", err)

    auth_service.store_otp(user['_id'], otp)
    return response_with_code(200, "OTP sent successfully")
    
def Reset_password():
    try:
        data = ResetPasswordSchema(**request.get_json())
    except ValidationError as e:
        return response_with_code(400, "Validation error", e.errors())

    if data.new_password != data.confirm_password:
        return response_with_code(400, "Passwords do not match")

    auth_service = AuthService(current_app.db)

    user = auth_service.find_user_by_otp(data.otp)
    if not user or not auth_service.verify_otp(user, data.otp):
        return response_with_code(400, "Invalid or expired OTP")

    success = auth_service.update_password(user['_id'], data.new_password)
    if not success:
        return response_with_code(500, "Failed to update password")

    auth_service.store_otp(user['_id'], None)  # Clear OTP after reset

    return response_with_code(200, "Password reset successfully")
