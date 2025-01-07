# Use the official Python image from Docker Hub
FROM python:3.8-slim

# Set the working directory inside the container
WORKDIR /action

# Copy the Python script and requirements file into the container
COPY main.py /action/main.py
COPY requirements.txt /action/requirements.txt

# Install the required dependencies
RUN pip install -r /action/requirements.txt

# Set the entrypoint for the action (what to run when the action is triggered)
ENTRYPOINT ["python", "/action/main.py"] > ${GITHUB_WORKSPACE}/output.txt
