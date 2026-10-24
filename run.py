import os
from dotenv import load_dotenv
from app import create_app
from app.extensions import db
from app.utils.migrations import apply_db_migrations

# Load environment variables from .env if present
load_dotenv()

app = create_app()

with app.app_context():
    # Automatically initialize and migrate database schema
    apply_db_migrations()

if __name__ == '__main__':
    # Local development server
    port = int(os.environ.get('PORT', 5000))
    app.run(host='127.0.0.1', port=port, debug=True)
