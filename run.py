import os
from flaskapp import app, db

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    with app.app_context():
        db.drop_all()
        db.create_all()
    app.run(host="0.0.0.0", port=port)