"""路由模块"""
from flask import Blueprint

auth_bp = Blueprint('auth', __name__)
files_bp = Blueprint('files', __name__)
policy_bp = Blueprint('policy', __name__)

from routes import auth_routes, file_routes, policy_routes
