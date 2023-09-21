import unittest
from flask_login import login_user
from app import app, db
from config import TestConfig
from models import User


class YourAppTestCase(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.app.config.from_object(TestConfig)
        self.app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF back
        self.app_context.pop()

    def test_user_registration(self):
        data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'username': 'johndoe',
            'email': 'john@example.com',
            'phone': '1234567890',
            'profile_visibility': 'public',
            'password': 'password123',
            'confirm_password': 'password123'
        }
        response = self.client.post('/register', data=data, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        # Adjust the flash message as per your application
        self.assertIn(b'A confirmation email has been sent to your email address.', response.data)

    def test_user_login(self):
        user = User(
            first_name='John',
            last_name='Doe',
            username='john',
            email='john@example.com',
            phone='1234567890',
            profile_visibility='Public',
            email_verified=True  # Make sure to set this to True
        )
        user.set_password('password')
        db.session.add(user)
        db.session.commit()

        response = self.client.post('/login', data={
            'email': 'john@example.com',
            'password': 'password'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'welcome, john!', response.data.lower())

    def test_report_item(self):
        user = User(
            first_name='John', last_name='Doe', username='john',
            email='john@example.com', phone='1234567890',
            profile_visibility='Everyone', email_verified=True
        )
        user.set_password('password')
        db.session.add(user)
        db.session.commit()

        with self.client:
            self.client.post('/login', data={
                'email': 'john@example.com',
                'password': 'password'
            }, follow_redirects=True)

            response = self.client.post('/report_item', data={
                'description': 'Lost wallet',
                'category': 'Wallet',
                'location': 'Park',
                'type': 'lost'
            }, follow_redirects=True)

            self.assertEqual(response.status_code, 200)
            self.assertIn(b'welcome, john!', response.data.lower())


if __name__ == '__main__':
    unittest.main()
