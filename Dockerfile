FROM python:alpine

# Install required dependencies
RUN pip install --no-cache-dir \
requests \
kubernetes \
pyOpenSSL

# Create app directory
WORKDIR /app

# Copy the script
COPY update_cert.py .

# Set default command
CMD ["python", "/app/update_cert.py"]
