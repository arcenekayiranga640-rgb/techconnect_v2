import sqlite3  
conn = sqlite3.connect('techconnect')  
cursor = conn.cursor()  
cursor.execute("CREATE TABLE IF NOT EXISTS portfolio_images (id INTEGER PRIMARY KEY AUTOINCREMENT, technician_id INTEGER, image_url TEXT, caption TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")  
cursor.execute("CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, technician_id INTEGER, client_name TEXT, rating INTEGER, comment TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")  
try: cursor.execute("ALTER TABLE users ADD COLUMN is_available INTEGER DEFAULT 1")  
except: pass  
conn.commit()  
conn.close()  
with open('app.py', 'r') as f: content = f.read()  
with open('patch.py', 'r') as f: code = f.read()  
if 'init_db()' not in content:  
    with open('app.py', 'a') as f: f.write("\n\ndef init_db():\n" + "\n".join("    " + line for line in code.splitlines()[:8]) + "\n\ninit_db()\n")  
