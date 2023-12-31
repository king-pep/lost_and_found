# Lost and Found Web Application

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Local Setup](#local-setup)
  - [Docker Setup](#docker-setup)
- [Usage](#usage)
- [Email Configuration](#email-configuration)
- [Contributing](#contributing)
- [License](#license)

## Features
- **Search for Lost and Found Items**: Users can search for items based on keywords, categories, locations, and date ranges.
- **Claim Ownership of Items**: Users can claim ownership of lost items by submitting proof of ownership.
- **Email Notifications**: The application sends email notifications when potential matches are found for claimed items.
- **User Authentication**: Users can create accounts, log in, and access personalized features.
- **Messaging**: Users can communicate with each other via real-time chat.

## Prerequisites
- Docker and Docker Compose
- Python 3.x (if running locally)
- PostgreSQL or another relational database (if running locally)
- SMTP email service (for email notifications)

## Installation

### Local Setup
1. Clone the repository:
   ```shell
   git clone https://github.com/king-pep/lost-and-found-app.git
   cd lost-and-found-app
    ```
   

2. Create a virtual environment (recommended) and install dependencies:
   ```shell
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Create and configure the `.env` file based on the provided `.env.example`.
4. Create the database and apply migrations:
   ```shell
   flask db init
   flask db migrate
   flask db upgrade
   ```
5. Start the application:
   ```shell
   flask run
   ```

### Docker Setup
1. Clone the repository:
   ```shell
   git clone https://github.com/king-pep/lost-and-found-app.git
   cd lost-and-found-app
   ```
2. Create and configure the `.env` file based on the provided `.env.example`.
3. Build and run the Docker containers:
   ```shell
   docker-compose up --build
   ```
4. Open a new terminal window and apply the database migrations:
   ```shell
   docker-compose exec web flask db upgrade
   ```

## Usage
1. Open the application in your web browser at `http://localhost:8000` (or `http://localhost:5000` if running locally).
2. Register for an account or log in if you already have one.
3. Use the search functionality to find lost and found items. You can filter results by keywords, categories, location, and date range.
4. Claim ownership of a lost item by providing proof of ownership.
5. Receive email notifications when potential matches are found for claimed items.
6. Explore other features such as real-time chat with other users.

## Email Configuration
The application sends email notifications when potential matches are found for claimed items. To configure the email service, modify the `config.py` file with your email server details and credentials.

## Contributing
Contributions to this project are welcome. To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix:
   ```shell
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes and push to your forked repository:
   ```shell
   git commit -m "Add your feature"
   git push origin feature/your-feature-name
   ```
4. Create a pull request from your forked repository to the main project repository.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
