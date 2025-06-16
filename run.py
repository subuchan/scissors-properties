from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

# Allow only your production frontend domain
CORS(app, origins=["https://scissorsproperties.com"], supports_credentials=True)
