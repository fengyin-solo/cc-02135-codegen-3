"""路由模块"""
from flask import Blueprint

auth_bp = Blueprint('auth', __name__)
files_bp = Blueprint('files', __name__)
policies_bp = Blueprint('policies', __name__)

from routes import auth_routes, file_routes, policy_routes
