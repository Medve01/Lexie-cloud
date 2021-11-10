aws-vault exec bear-services -- aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 149600605513.dkr.ecr.us-east-1.amazonaws.com
docker build -t lexie-cloud .
docker tag lexie-cloud:latest 149600605513.dkr.ecr.us-east-1.amazonaws.com/lexie-cloud:latest
docker push 149600605513.dkr.ecr.us-east-1.amazonaws.com/lexie-cloud:latest
