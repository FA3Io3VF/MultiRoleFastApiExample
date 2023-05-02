import uvicorn
from getpass import getpass
import re
import os
import jwt
from jose import JWTError, jwt, JWSError
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import sessionmaker, relationship, Session, mapper
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import declarative_base
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta, date
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ARRAY, text 
from sqlalchemy import Table, UniqueConstraint, PrimaryKeyConstraint, ForeignKey
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from loguru import logger 
from sqlalchemy.sql.expression import or_
from sqlalchemy import join
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import func
from fastapi.responses import PlainTextResponse, RedirectResponse

import schemas
from models import Base, User, Profile, Sector, Role, Route, UserProfile, ProfileSector, SectorRole, RoleRoute
from schemas import Token, BaseModel, ProfileCreate, RoleCreate, SectorCreate, UserCreate, SuperUserCreate,\
    UserData, UserLogin, ProfileBase, ProfileOut, RoleBase, RoleOut, RouteBase, RouteOut, SectorBase, \
    SectorOut, UserBase, UserOut, RoleRouteCreate, UserProfileCreate, ProfileSectorCreate, SectorRoleCreate

from logManagment import logger
from support import isConnected, getNow
from env import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, DEBUG_MODE, NO_GUI, SECRET_KEY, SQLALCHEMY_DATABASE_URL


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={
                       "check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(
    title="MultiLevel Role Autorizzation BoilerPlate",
    description="Test Application",
    version="0.0.1",
    debug=DEBUG_MODE
    )


import inspect
def get_function_name():
    return inspect.stack()[1][3]

import traceback
def print_stack_trace():
    stack_trace = traceback.format_stack()
    for line in stack_trace:
        print(line.strip())

if NO_GUI:    
    from fastapi.responses import RedirectResponse
    @app.exception_handler(404)
    async def custom_404_handler(_, __):
        return RedirectResponse("/docs")

if DEBUG_MODE:
    origins = ["*"]
else:
    origins = [
    "http://localhost.myserver.ext",
    "https://localhost.myserver.ext",
    "http://localhost",
    "http://localhost:8080",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    max_age=3600,
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    logger.error(f"HTTPException - status_code: {exc.status_code}, details: {exc.detail}")
    return JSONResponse(status_code=exc.status_code, content={"message": exc.detail})

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    Base.metadata.create_all(bind=engine)

def check_tables():
    from sqlalchemy import inspect
    insp = inspect(engine)
    table_names = insp.get_table_names()
    required_tables = ['users','profiles', 'routes', 'roles', 'userprofiles', 'profilesectors', 'sectoroles', 'roleroutes']
    return all(table in table_names for table in required_tables)

@app.on_event("startup")
def startup_event():
    logger.info(f"Application: startup - Debug Mode: {DEBUG_MODE}")
    if not check_tables():
        create_tables()
        create_superuser_if_first_run()
    try:
        db = SessionLocal()
        db.execute(text('SELECT 1'))
    except:
        logger.error("DB Connection Test Failed")
        raise Exception("Unable to Connect to DB")
    finally:
        db.close()
    if not isConnected():
        logger.warning("No internet Connection")
        if not DEBUG_MODE:
            raise SystemExit
        
@app.on_event("shutdown")
async def shutdown_event():
   logger.info('Server Shutdown :', getNow())

def verify_password(plain_password, hashed_password, username):
    if not isinstance(plain_password, (str, bytes)) or not isinstance(hashed_password, (str, bytes)):
        return HTTPException(status_code=500, detail="Internal Server Error: data type mismatch")
    try:
        pwd_test = pwd_context.verify(plain_password, hashed_password)
    except:
        raise HTTPException(status_code=500, detail="Internal server error: hashing error")
    return pwd_test

def authenticate_user(username: str, password: str, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.username == username).first()
    except:
        return HTTPException(status_code=500, detail="Internal server error: Authentication Error")
    if not user:
        return False
    if not verify_password(password, user.password, user.username):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=22)
    to_encode.update({"exp": expire})
    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    except JWSError:
        raise HTTPException(status_code=500, detail="Internal server error: Token Creation Error")
    return encoded_jwt

@app.post("/ping")
async def ping():
    return PlainTextResponse("pong")

@app.get("/vigilfuoco", response_class=RedirectResponse, status_code=status.HTTP_302_FOUND)
async def redirect_vigilfuoco():
    return "https://vigilfuoco.it/"

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        #Here we pass the username because the id is an internal value not to be exported external
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

import re
@app.post("/register", response_model=UserCreate)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    if len(user.password) < 6 or not re.search(r'\d', user.password) or \
            not re.search(r'[!@#$%^&*(),.?":{}|<>]', user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Error: The password must have at least 6 characters,\
                                at least one symbol and at least one number")
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(
            status_code=400, detail="Error: Invalid username")
    if db.query(User).filter_by(username=user.username).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Error: Invalid id")
    email_regex = re.compile(r"[^@]+@[^@]+\.[^@]+")
    if not email_regex.match(user.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Error: Invalid")

    hashed_password = pwd_context.hash(user.password)
    db_user = User(username=user.username,
                    password=hashed_password, 
                    surname=user.surname, 
                    name=user.name, 
                    email=user.email,
                    )
    try:
        db.add(db_user)
        db.commit()
    except:
        db.rollback()
        raise HTTPException(status_code=400, detail="Errore Inserimento Dati")
    db.refresh(db_user)
    return db_user

async def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    try:
        user = session.query(User).filter_by(username=username).first()
    except:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="DataBase Error in authentication credentials checking",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    if not user:
        logger.error("Utente non trovato in: get_current_user")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid authentication credentials: User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user

@app.post("/self", response_model=UserData)
async def return_user(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):                                 
    logger.info(f'Request to {get_function_name()} at \
        {app.url_path_for(get_function_name())} - user: {current_user.username}')
    try:
        data = UserData(
            username=current_user.username,
            name=current_user.name,
            surname=current_user.surname,
            email=current_user.email,
            superuser=current_user.superuser,
            active=current_user.active
        )
    except:
        raise HTTPException(
            status_code=status.HTTP_406_NOT_ACCEPTABLE,
            detail="Internal Server Error: NOT_ACCEPTABLE",
            headers={"WWW-Authenticate": "Bearer"},
        )        
    return data

@app.post("/profiles", name="profiles", description='Endpoint to create a new Profile') #create new response model
async def create_profile(profile: ProfileCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user.superuser:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Not authorized to {get_function_name()} at \
                                {app.url_path_for(get_function_name())} - user: {current_user.username}")
    try:            
        db_profile = Profile(**profile.dict(), user_id=current_user.id)
        db.add(db_profile)
        db.commit()
        logger.error(f"Commit change in {get_function_name()} with data {profile.name} \
            - user: {current_user.username}")
    except:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Internal Database Error in {get_function_name()} \
                                - user: {current_user.username}")
    finally:
        db.refresh(db_profile)
    
    return {"message": "Profile created"}

@app.post("/sectors/", description='Endpoint to create a new Sector') #create new response model
def create_sector(sector: SectorCreate, db: Session = Depends(get_db), current_user: int = Depends(get_current_user)):
    if not current_user.superuser:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail=f"Not authorized to {get_function_name()} at \
                {app.url_path_for(get_function_name())} - user: {current_user.username}"
            )
    db_sector = Sector(**sector.dict())
    db.add(db_sector)
    db.commit()
    db.refresh(db_sector)
    return {"message": "Sector created"}

@app.post("/roles/", description='Endpoint to create a new Role') #create new response model
def create_role(role: RoleCreate, db: Session = Depends(get_db), current_user: int = Depends(get_current_user)):
    if not current_user.superuser:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                            detail=f"Not authorized to {get_function_name()} at \
                                {app.url_path_for(get_function_name())} - user: {current_user.username}"
                            )
    db_role = Role(**role.dict())
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return {"message": "Role created"}

@app.delete("/users/{user_id}", description='Endpoint to delete a user (only super user)')
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: int = Depends(get_current_user)):
    if not current_user.superuser:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                            detail=f"Not authorized to {get_function_name()} at \
                                {app.url_path_for(get_function_name())} - user: {current_user.username}"
                            )
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"User not found at \
            {get_function_name()} at {app.url_path_for(get_function_name())} - user: {current_user.username}")
    db.delete(db_user)
    db.commit()
    return {"message": "User deleted"}


@app.get("/users/", description='Endpoint to read basic user(s) profile', response_model=schemas.Users)
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = db.query(User).offset(skip).limit(limit).all()
    return users

@app.get("/profiles/", description='Endpoint to get all users Profile', response_model=schemas.UserProfiles)
def get_all_profiles(db: Session = Depends(get_db)):
    profiles = db.query(Profile).all()
    return profiles

@app.get("/sectors/", response_model=schemas.ProfileSectors)
def get_all_sectors(db: Session = Depends(get_db)):
    sectors = db.query(Sector).all()
    return sectors

@app.get("/roles/", response_model=schemas.SectorRoles)
def get_all_roles(db: Session = Depends(get_db)):
    roles = db.query(Role).all()
    return roles

@app.get("/routes/", response_model=schemas.RoleRoutes)
def get_all_routes(db: Session = Depends(get_db)):
    routes = db.query(Route).all()
    return routes

# Routes to create associations between users, profiles, sectors, and roles

@app.post("/userprofiles/")
def create_user_profile(user_profile: UserProfileCreate, db: Session = Depends(get_db)):
    db_user_profile = UserProfile(**user_profile.dict())
    db.add(db_user_profile)
    db.commit()
    db.refresh(db_user_profile)
    return db_user_profile

@app.post("/profilesectors/")
def create_profile_sector(profile_sector: ProfileSectorCreate, db: Session = Depends(get_db)):
    db_profile_sector = ProfileSector(**profile_sector.dict())
    db.add(db_profile_sector)
    db.commit()
    db.refresh(db_profile_sector)
    return db_profile_sector

@app.post("/sectoroles/")
def create_sector_role(sector_role: SectorRoleCreate, db: Session = Depends(get_db)):
    db_sector_role = SectorRole(**sector_role.dict())
    db.add(db_sector_role)
    db.commit()
    db.refresh(db_sector_role)
    return db_sector_role

@app.post("/roleroutes/")
def create_role_route(role_route: RoleRouteCreate, db: Session = Depends(get_db)):
    db_role_route = RoleRoute(**role_route.dict())
    db.add(db_role_route)
    db.commit()
    db.refresh(db_role_route)
    return db_role_route
    
@app.get("/routes/")
async def get_routes(db: Session = Depends(get_db)):
    db_routes = db.query(Route).all()
    return {"routes": [r.as_dict() for r in db_routes]}

@app.get("/roles/")
async def get_roles(db: Session = Depends(get_db)):
    db_roles = db.query(Role).all()
    return {"roles": [r.__dict__ for r in db_roles]}

@app.post("/users/{user_id}/profiles/{profile_id}", status_code=204)
def add_user_profile(user_id: int, profile_id: int, motivation: str = None, db: Session = Depends(get_db)):
    user = db.query(User).get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    profile = db.query(Profile).get(profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    user_profile = UserProfile(user_id=user_id, profile_id=profile_id, motivation=motivation)
    db.add(user_profile)
    try:
        db.commit()
    except IntegrityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="User is already associated with this profile"
            )

@app.post("/profiles/{profile_id}/sectors/{sector_id}", status_code=204)
def add_profile_sector(profile_id: int, sector_id: int, motivation: str = None, db: Session = Depends(get_db)):
    profile = db.query(Profile).get(profile_id)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")
    sector = db.query(Sector).get(sector_id)
    if sector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sector not found")
    user_profile = db.query(UserProfile).filter_by(profile_id=profile_id).first()
    if user_profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="No user is associated with this profile"
            )
    profile_sector = ProfileSector(
        userprofile_id=user_profile.id, 
        sector_id=sector_id, 
        motivation=motivation)
    db.add(profile_sector)
    try:
        db.commit()
    except IntegrityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="This profile is already associated with this sector"
            )

def get_user_by_username(db: Session, username: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user_profiles = db.query(UserProfile).filter(UserProfile.user_id == user.id).all()
    profiles = []
    for user_profile in user_profiles:
        profile = db.query(Profile).filter(Profile.id == user_profile.profile_id).first()
        profile_sectors = db.query(ProfileSector).filter(ProfileSector.userprofile_id == user_profile.id).all()
        sectors = []
        for profile_sector in profile_sectors:
            sector = db.query(Sector).filter(Sector.id == profile_sector.sector_id).first()
            sector_roles = db.query(SectorRole).filter(SectorRole.profilesector_id == profile_sector.id).all()
            roles = []
            for sector_role in sector_roles:
                role = db.query(Role).filter(Role.id == sector_role.role_id).first()
                role_routes = db.query(RoleRoute).filter(RoleRoute.sectorRole_id == sector_role.id).all()
                routes = []
                for role_route in role_routes:
                    route = db.query(Route).filter(Route.id == role_route.route_id).first()
                    routes.append(route.as_dict())
                role_data = RoleOut(**role.as_dict(), routes=routes)
                roles.append(role_data)
            sector_data = SectorOut(**sector.as_dict(), roles=roles)
            sectors.append(sector_data)
        profile_data = ProfileOut(**profile.as_dict(), sectors=sectors)
        profiles.append(profile_data)
    user_data = UserOut(**user.as_dict(), profiles=profiles)
    return user_data


# Route to get the data of a user (superuser) or your own data
@app.get("/users/{username}", response_model=UserOut)
async def read_user_by_username(username: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    if username != current_user.username:        
        if not current_user.superuser:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                detail=f"Not authorized to {get_function_name()} at \
                                    {app.url_path_for(get_function_name())} - user: {current_user.username}"
                                )
    user = get_user_by_username(db, username)
    return user

"""
Route            : /users/{username}
Function         : read_user_by_username
Response         : UserOut

Response Example :

{
    "id": 1,
    "username": "johndoe",
    "name": "John",
    "surname": "Doe",
    "email": "john.doe@example.com",
    "superuser": false,
    "creator": "Admin",
    "id_creator": 1,
    "creation_date": "2022-01-01",
    "active": true,
    "only_observer": false,
    "defaultSector": 2,
    "profiles": [
        {
            "id": 1,
            "name": "Full Stack Developer",
            "description": "Developer with knowledge of both front-end and back-end technologies",
            "sectors": [
                {
                    "id": 1,
                    "name": "Technology",
                    "description": "Technology and IT sector",
                    "reserved": false,
                    "roles": [
                        {
                            "id": 1,
                            "name": "Developer",
                            "description": "Software Developer",
                            "routes": [
                                {
                                    "id": 1,
                                    "name": "View dashboard",
                                    "path": "/dashboard",
                                    "description": "View the dashboard",
                                    "active": true
                                },
                                {
                                    "id": 2,
                                    "name": "Edit profile",
                                    "path": "/profile/edit",
                                    "description": "Edit user profile",
                                    "active": true
                                }
                            ]
                        },
                        {
                            "id": 2,
                            "name": "Administrator",
                            "description": "System Administrator",
                            "routes": [
                                {
                                    "id": 1,
                                    "name": "View dashboard",
                                    "path": "/dashboard",
                                    "description": "View the dashboard",
                                    "active": true
                                },
                                {
                                    "id": 3,
                                    "name": "Manage users",
                                    "path": "/users",
                                    "description": "Manage user accounts",
                                    "active": true
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    ]
}
"""

def create_superuser_if_first_run():
    filename = "setup.dat"
    if os.path.isfile(filename):
        logger.info("Avvio standard")
        return
    else:
        logger.info("Primo avvio dell'applicazione.")

        if not DEBUG_MODE:
            # TODO: Questa funzione andrà nel programma di installazione
            print("\nInserire password di super amministratore")
            password = getpass()
            
            print("\nInserire email per il super amministratore")
            email = str(input())
        else:
            password="1Unsafe.Password"
            email = "emailtest@testemail.com"

        # Creazione dell'utente superuser
        suser = SuperUserCreate(
            username="admin",
            name="Admin",
            surname="Admin",
            password=password,
            email=email,
            superuser=True,
            active=True,
        )

        try:
            db = SessionLocal()
            hashed_password = pwd_context.hash(suser.password)
            db_user = User(
                username=suser.username,
                name=suser.name,
                surname=suser.surname,
                password=hashed_password,
                email=suser.email,
                superuser=suser.superuser,
                active=suser.active
            )
            
            try:
                db.add(db_user)
                db.commit()
            except IntegrityError:
                db.rollback()
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                    detail="Internal Error in First Run")
            finally:
                db.refresh(db_user)
            
            with open(filename, "w") as f:
                f.write(f"\nSetup completed: {getNow()}")

            logger.info("Superuser Created.")

        except:
            db.rollback()
            logger.error(f"Error in Superuse Creation - {getNow()}")
            raise Exception("Error in Superuse Creation")


# Function to activate a user (superuser only)
@app.put("/users/{username}/activate")
async def activate_user(username: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    if username != current_user.username:        
        if not current_user.superuser:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                detail=f"Not authorized to {get_function_name()} at \
                                    {app.url_path_for(get_function_name())} - user: {current_user.username}"
                                )
    db_user = db.query(User).filter_by(username=username).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    db_user.active = True
    db.commit()
    return {"message": "User activated"}

# Function to deactivate a user (superuser only)
@app.put("/users/{username}/deactivate")
async def deactivate_user(username: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    if username != current_user.username:        
        if not current_user.superuser:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                detail=f"Not authorized to {get_function_name()} at \
                                    {app.url_path_for(get_function_name())} - user: {current_user.username}"
                                )
    db_user = db.query(User).filter_by(username=username).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"User not found at: {get_function_name()} at \
                                    {app.url_path_for(get_function_name())} - user: {current_user.username}"
                                )
    db_user.active = False
    db.commit()
    return {"message": "User deactivated"}

# Function to give superuser privileges to a user (superuser only)
@app.put("/users/{username}/superuser")
async def give_superuser(username: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    if username != current_user.username:        
        if not current_user.superuser:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                detail=f"Not authorized to {get_function_name()} at \
                                    {app.url_path_for(get_function_name())} - user: {current_user.username}"
                                )
    db_user = db.query(User).filter_by(username=username).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"User not found at: {get_function_name()} at \
                                    {app.url_path_for(get_function_name())} - user: {current_user.username}"
                                )
    db_user.superuser = True
    db.commit()
    return {"message": "User is now a superuser"}

# Function to change a user's password (superuser only)
@app.put("/users/{username}/password")
async def change_password(username: str, new_password: str, db: Session = Depends(get_db), current_user = Depends(get_current_user)):
    if username != current_user.username:        
        if not current_user.superuser:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                detail=f"Not authorized to {get_function_name()} at \
                                    {app.url_path_for(get_function_name())} - user: {current_user.username}"
                                )
    db_user = db.query(User).filter_by(username=username).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"User not found at: {get_function_name()} at \
                                    {app.url_path_for(get_function_name())} - user: {current_user.username}"
                                )
    db_user.password = new_password
    db.commit()
    return {"message": "Password changed successfully"}


# uvicorn oldlifm:app --reload --port 8000
if __name__ == '__main__':
    uvicorn.run(app, port=8989)
