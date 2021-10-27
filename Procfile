web: python -c "from website.db import init_db; init_db()"; gunicorn main:app
web: gunicorn -w 1 --threads 100 main:app