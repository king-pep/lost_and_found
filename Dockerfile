# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container to /app
WORKDIR /app

# Set up a virtual environment
RUN python -m venv venv

# Copy only the requirements file and install the dependencies
COPY requirements.txt .
RUN . venv/bin/activate && pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . /app

# Create a non-root user and change the ownership of the app files
RUN useradd -m myuser && chown -R myuser /app
USER myuser

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Use the virtual environment to run gunicorn when the container launches
CMD [ "venv/bin/gunicorn", "-b", "0.0.0.0:8000", "app:app" ]
