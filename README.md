# I. Create and Start Project

### 1. Start Miniconda base to use Python and Install library

### 2. Pip install requirements.txt

```bash
pip install -r requirements.txt
```

### 3. Create Django Project & App

```bash
django-admin startproject wapiti_web .
cd wapiti_web
python manage.py startapp scanner
```

- Creates a new Django project named **wapiti_web**
- Creates a specific, isolated component (called an **app** in Django) named **scanner** inside this project.

### 4. Migrate Table and Database to db.sqlite3

```bash
python manage.py makemigrations scanner
python manage.py migrate
```

### 5. Collect / Build Tailwind CSS  (downloads CLI binary automatically)

```bash
python manage.py tailwind build
```

### 6. Run command

Open 3 separate terminals, to help monitor job

- Terminal 1 — Tailwind watch (rebuilds CSS on template save)
```bash
python manage.py tailwind watch
```

- Terminal 2 — Celery worker
    - info
    - error
    - debug

```bash
# Windows
celery -A wapiti_web worker --loglevel=info -P solo

# Linux/Mac
celery -A wapiti_web worker --loglevel=info
```

- Terminal 3 — Django dev server
```bash
python manage.py runserver 8080
```

### 6. Cancel Scan and Purge Queue command

```bash
# Reset ALL stuck jobs
python manage.py cleanup_scans

# Reset + purge Celery queue
python manage.py cleanup_scans --purge-queue

# Only reset jobs stuck longer than 10 minutes
python manage.py cleanup_scans --older-than 10 --purge-queue
```