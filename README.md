## create .env file with following keys

JWT_SECRET_KEY=mysecretkey \
JWT_REFRESH_SECRET_KEY=myrefreshkey 

## create venv
python -m venv env \
env\Scripts\activate 

## install requirements
pip install -r requirements.txt

## run web server
uvicorn app:app --host 0.0.0.0 --port 8080
