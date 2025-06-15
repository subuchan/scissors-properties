from flask import Blueprint
from app.admin_controller.admin import (admin_create,admin_login,forgot_password,change_password,
reset_password,get_pending_users,approve_user,decline_user,get_all_login_requests,handle_login_request)

admin_bp=Blueprint('admin_bp',__name__)

admin_bp.route('/create-admin',methods=['POST'])(admin_create)
admin_bp.route('/admin-login',methods=['POST'])(admin_login)
admin_bp.route('/admin-change-password', methods=['PUT'])(change_password)
admin_bp.route('/admin-forgot-password', methods=['POST'])(forgot_password)
admin_bp.route('/admin-reset-password', methods=['POST'])(reset_password)

admin_bp.route('/decline/<user_id>', methods=['POST'])(decline_user)
admin_bp.route('/approve/<user_id>', methods=['POST'])(approve_user)
admin_bp.route('/pending-users', methods=['GET'])(get_pending_users)
admin_bp.route('/requests', methods=['GET'])(get_all_login_requests)
admin_bp.route('/handle-request', methods=['POST'])(handle_login_request)


