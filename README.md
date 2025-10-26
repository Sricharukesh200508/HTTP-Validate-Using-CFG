# HTTP-Validate-Using-CFG
A simple yet powerful Flask web application that allows users to sign up, log in, and validate HTTP requests.
It’s built using Python, Flask, SQLite, and ready to integrate machine learning–based anomaly detection for detecting malicious or invalid HTTP requests.

🚀 Features
✅ User authentication (Signup & Login)
✅ Password hashing for security (using Werkzeug)
✅ SQLite database integration
✅ HTTP request validation route (extendable with ML)
✅ Simple and clean HTML templates
✅ Flash messages for user feedback
✅ Scalable and ready for future ML model integration

⚙️ Installation & Setup
1️⃣ Clone the Repository
git clone https://github.com/<your-username>/HTTP_CN3.git
cd HTTP_CN3
2️⃣ Create a Virtual Environment
python -m venv venv
venv\Scripts\activate        # For Windows
source venv/bin/activate     # For macOS/Linux
3️⃣ Install Dependencies
pip install flask flask_sqlalchemy flask_login werkzeug
4️⃣ Run the App
python app.py

Your app will start at:
👉 http://127.0.0.1:5000

🧰 Technologies Used
Component	Technology
Backend	Flask (Python)
Database	SQLite
🧾 License

This project is licensed under the MIT License — feel free to modify and use it for your own learning or projects.
Frontend	HTML, CSS
Authentication	Flask-Login, Werkzeug
Optional ML	scikit-learn / TensorFlow (future)
