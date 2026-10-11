import sqlite3
conn = sqlite3.connect('techconnect')
cursor = conn.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT, phone TEXT, bio TEXT, category TEXT, location TEXT, is_available INTEGER DEFAULT 1)')
cursor.execute('CREATE TABLE IF NOT EXISTS portfolio_images (id INTEGER PRIMARY KEY AUTOINCREMENT, technician_id INTEGER, image_url TEXT, caption TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
cursor.execute('CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, technician_id INTEGER, client_name TEXT, rating INTEGER, comment TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
try:
    cursor.execute('ALTER TABLE users ADD COLUMN is_available INTEGER DEFAULT 1')
except:
    pass
conn.commit()
conn.close()
print("Database initialized successfully!")
