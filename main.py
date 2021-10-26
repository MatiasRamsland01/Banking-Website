from website import create_app
from website.db import db
app = create_app()
if __name__ == '__main__':
    app.run(debug=True)
    db.create_all()
