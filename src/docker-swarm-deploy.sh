#!/bin/bash

# Load the image
docker load < ./spell-check-web-v1.0

# # Or to build image accoding Dockerfile, use docker-compose.yml
# docker-compose build

# Create a new docker swarm to deploy multiple services
docker swarm leave --force && docker swarm init

# Create new docker secrets
echo admin | docker secret create admin_password -
echo CS9163Assignment02WebsiteFlaskSessionSecretKey | docker secret create flask_session_secret_key -
echo CS9163Assignment02WebsiteFlaskWTFCSRFToken | docker secret create flask_wtf_csrf_token -

# --limit-cpu : limitation on CPU for each service
# --limit-memory : limitation on memory for each service
# 
# --secret : specify secrets that will be used for these services.
#         In this application, there are 3 secrets:
#           1. admin_password
#           2. flask_session_secret_key
#           3. flask_wtf_csrf_token
#         Default value for these secrets are pre-defined in app.py.
# 
# src_web : the name of the image should be the same of the image that has been previously built.
#         src_web is because this image was built according to docker-compose.yml,
#         where the name is "web".
docker service create --replicas 4 --limit-cpu 0.25 --limit-memory 100M --secret admin_password flask_session_secret_key flask_wtf_csrf_token --name spell-check-web -p 8080:5000 src_web:latest