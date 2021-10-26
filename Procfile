web: python -c "from website.db import init_db; init_db()"
web: gunicorn -w 1 --threads 100 main:app