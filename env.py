"""
os.environ["DEBUG_MODE"] = "True"
os.environ["SECRET_KEYY"] = "------------------"
#print(os.environ["DEBUG_MODE"])
SECRET_KEY = os.environ.get("SECRET_KEY")
DEBUG_MODE = os.environ.get("DEBUG_MODE")

Creating secret in production openssl rand -hex 32
"""

SECRET_KEY="-----------"
DEBUG_MODE = True
NO_GUI = True

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


SQLALCHEMY_DATABASE_URL = "sqlite:///./dbname.db"
