class Config:
    # SECRET_KEY = 'secretkey'
    IMAGE_UPLOAD_FOLDER = 'static/images'
    CLAIMS_DOCUMENT_UPLOAD_FOLDER = 'static/claims_documents'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    # Mail Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USERNAME = 'EMAIL_ADDRESS'  # Replace with your actual email
    MAIL_PASSWORD = 'MAIL_PASSWORD'  # Replace with your actual password
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db'
    # WTF_CSRF_ENABLED = False
    SERVER_NAME = 'localhost.localdomain:5000'

