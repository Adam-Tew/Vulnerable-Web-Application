# Base Image: Minimal Python
FROM python:3.12-slim

# Set environment variables for security
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Set the working directory inside the container
WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root user for security
RUN useradd -ms /bin/bash flaskuser

# Copy only the obfuscated files and necessary resources
COPY dist/main.py /app/main.py
COPY dist/pyarmor_runtime_000000 /app/pyarmor_runtime_000000
COPY templates /app/templates
COPY static /app/static
COPY vulnerable_union.db /app/vulnerable_union.db
COPY vulnerable.db /app/vulnerable.db
COPY vulnerable_blacklist_filtering.db /app/vulnerable_blacklist_filtering.db
COPY vulnerable_double_encoding.db /app/vulnerable_double_encoding.db
COPY vulnerable_url_encoding.db /app/vulnerable_url_encoding.db
COPY flag.db /app/flag.db
COPY uenumrestim.db /app/uenumrestim.db
COPY etc /app/etc

# Set the ownership of all app files to flaskuser
RUN chown -R flaskuser:flaskuser /app

# Switch to the non-root user
USER flaskuser

# Expose the port Flask will run on
EXPOSE 5000

# Prevent interactive shell access
ENTRYPOINT ["python"]
CMD ["main.py"]
