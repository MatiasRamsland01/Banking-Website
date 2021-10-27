web: python -c "from website import init_db; init_db()"; gunicorn main:app
web: gunicorn -w 1 --threads 100 main:app