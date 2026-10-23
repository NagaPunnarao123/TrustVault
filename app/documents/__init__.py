from flask import Blueprint

documents_bp = Blueprint('documents', __name__, url_prefix='/documents')

from app.documents import routes
