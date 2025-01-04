# Step 1: Use Python 3.10 as the base image
FROM python:3.10-slim

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Copy requirements.txt into the container
COPY requirements.txt /app/

# Step 4: Install dependencies
# RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Copy the rest of your application code into the container
COPY . /app/

# Step 6: Expose the port your app will run on
EXPOSE 5001

# Step 7: Define the entry point to run your application
CMD ["python", "app.py"]
