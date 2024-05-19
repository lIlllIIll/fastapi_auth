# My fastAPI app
Just an app for authorization using jwt tokens as protection.
You can use it for registration, login, getting, updating and deleting user info.
It uses db to storage user info.
## How to launch
1. Clone project ```git clone https://github.com/lIlllIIll/fastapi_auth.git```
2. Create venv
3. Install requirements ```pip install requirements.txt```
4. Add dburl to connect your db in config
5. Add secret key for jwt in config
6. Launch server ```uvicorn auth.main:app --reload```
7. Follow the link http://127.0.0.1:8000/docs to check endpoints
