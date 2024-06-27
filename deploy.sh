#!/bin/bash


# Update and install dependencies
sudo apt-get update
sudo apt-get install -y python3-pip

# Change to the deployment directory
# shellcheck disable=SC2164
cd /Users/V\ V/pythonProject/shop

# Pull the latest changes from the repository
git pull

# Install dependencies
pip install -r requirements.txt

# Apply database migrations (if any)
# python manage.py migrate  # Uncomment if using Django
# alembic upgrade head  # Uncomment if using Alembic

# Restart the application
# Assuming you are using a process manager like systemd or supervisor
sudo systemctl restart my_application  # Update with your service name

echo "Deployment completed successfully."
