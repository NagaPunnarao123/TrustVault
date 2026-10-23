import os
from dotenv import load_dotenv
from app import create_app
from app.extensions import db

# Load environment variables from .env if present
load_dotenv()

app = create_app()

with app.app_context():
    # Automatically initialize SQLite database tables if not existing
    db.create_all()

if __name__ == '__main__':
    # Local development server
    port = int(os.environ.get('PORT', 5000))
    app.run(host='127.0.0.1', port=port, debug=True)
