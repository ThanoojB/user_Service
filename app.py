from flask import Flask
from flask_cors import CORS
from auth_service import auth_bp
from flask_jwt_extended import JWTManager

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = '92093ad483ee8d15dfe55e80d79afb59dde5a48cde8150590c6e4155a7207139'
jwt = JWTManager(app)

app.register_blueprint(auth_bp, url_prefix='/auth')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, use_reloader=False)
