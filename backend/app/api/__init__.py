"""
API blueprint initialization.
"""
from flask import Blueprint

# Create blueprints
auth_bp = Blueprint('auth', __name__)
patients_bp = Blueprint('patients', __name__)
monitoring_bp = Blueprint('monitoring', __name__)

# Import routes
from . import auth  # This imports the routes from auth.py

# Import the routes for other blueprints when they are created
# from . import patients
# from . import monitoring