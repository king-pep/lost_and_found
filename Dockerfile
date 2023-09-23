# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container to /app
WORKDIR /app

# Set up a virtual environment
RUN python -m venv venv

# Copy the current directory contents into the container at /app
COPY . /app

# Activate the virtual environment and install the dependencies
RUN . venv/bin/activate && pip install --no-cache-dir -r requirements.txt

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Use the virtual environment to run gunicorn when the container launches
CMD [ "venv/bin/gunicorn", "-b", "0.0.0.0:8000", "app:app" ]
