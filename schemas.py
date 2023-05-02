from pydantic import BaseModel, EmailStr
from typing import Optional, List

"""
List of models Pydenatic: Pydantic is a data validation 
and serialization framework and relies on class 
annotations to define validation schemes of the
input data and to describe the output data.
"""

class Token(BaseModel):
    access_token: str
    token_type: str

# Modello per la creazione di un utente
class UserCreate(BaseModel):
    username: str
    name: str
    surname: str
    password: str
    email: EmailStr

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "username": "AnExampleUsername",
                "name": "my name",
                "surname": "my surname",
                "password": "weakpassword",
                "email": "avalidemail@servermail.com"
            }
        }

class SuperUserCreate(BaseModel):
    username: str
    name: str
    surname: str
    password: str
    email: EmailStr
    superuser: Optional[bool] = True
    active: Optional[bool] = True
    class Config:
        orm_mode = True

# Modello per il login di un utente
class UserLogin(BaseModel):
    username: str
    password: str
    class Config:
        orm_mode = True
        
# Modello per dati utente generici
class UserData(BaseModel):
    username: str
    name: str
    surname: str
    email: EmailStr
    superuser: Optional[bool] = True
    active: Optional[bool] = True
    class Config:
        orm_mode = True
        
        
# Modello per la creazione di un profilo
class ProfileCreate(BaseModel):
    name: str
    description: Optional[str] = None
    active: Optional[bool] = False
    default_sector_id: int
    only_observer: Optional[bool] = True
    user_id: int
    class Config:
        orm_mode = True

# Modello per la creazione di un settore
class SectorCreate(BaseModel):
    name: str
    description: Optional[str] = None
    reserved: Optional[bool] = True
    class Config:
        orm_mode = True

# Modello per la creazione di un ruolo
class RoleCreate(BaseModel):
    name: str
    sector_id: int
    class Config:
        orm_mode = True
    
class RouteBase(BaseModel):
    name: str
    path: str
    description: str
    active: bool

class RouteOut(RouteBase):
    id: int

class RoleBase(BaseModel):
    name: str
    description: str

class RoleOut(RoleBase):
    id: int
    routes: List[RouteOut] = []

class SectorBase(BaseModel):
    name: str
    description: str
    reserved: bool

class SectorOut(SectorBase):
    id: int
    roles: List[RoleOut] = []

class ProfileBase(BaseModel):
    name: str
    description: str

class ProfileOut(ProfileBase):
    id: int
    sectors: List[SectorOut] = []

class UserBase(BaseModel):
    username: str
    name: str
    surname: str
    email: str
    superuser: bool
    creator: str
    id_creator: int
    creation_date: str
    active: bool
    only_observer: bool
    defaultSector: int

class UserOut(UserBase):
    id: int
    profiles: List[ProfileOut] = []
    
# ---------------------



# Schema per creare un'istanza di Route
class RouteCreate(BaseModel):
    name: Optional[str]
    path: str
    description: str

# Schema per creare un'istanza di Role
class RoleCreate(BaseModel):
    name: str
    description: Optional[str]

# Schema per creare un'istanza di Sector
class SectorCreate(BaseModel):
    name: str
    description: Optional[str]
    reserved: Optional[bool]

# Schema per creare un'istanza di UserProfile
class UserProfileCreate(BaseModel):
    user_id: int
    profile_id: int
    motivation: Optional[str]

# Schema per creare un'istanza di ProfileSector
class ProfileSectorCreate(BaseModel):
    userprofile_id: int
    sector_id: int
    motivation: Optional[str]

# Schema per creare un'istanza di SectorRole
class SectorRoleCreate(BaseModel):
    profilesector_id: int
    role_id: int
    motivation: Optional[str]

# Schema per creare un'istanza di RoleRoute
class RoleRouteCreate(BaseModel):
    sectorRole_id: int
    route_id: int
    motivation: Optional[str]

# Schema per la risposta di tutte le Route
class Route(BaseModel):
    id: int
    name: Optional[str]
    path: str
    description: str
    active: bool

    class Config:
        orm_mode = True

# Schema per la risposta di tutti i Role
class Role(BaseModel):
    id: int
    name: str
    description: Optional[str]

    class Config:
        orm_mode = True

# Schema per la risposta di tutti i Sector
class Sector(BaseModel):
    id: int
    name: str
    description: Optional[str]
    reserved: bool

    class Config:
        orm_mode = True

# Schema per la risposta di tutti i Profile
class Profile(BaseModel):
    id: int
    name: str
    description: Optional[str]

    class Config:
        orm_mode = True

# Schema per la risposta di un singolo User
class User(BaseModel):
    id: int
    username: str
    name: str
    surname: str
    email: str
    superuser: bool
    creator: Optional[str]
    id_creator: Optional[int]
    creation_date: Optional[str]
    active: bool
    only_observer: Optional[bool]
    defaultSector: Optional[int]

    class Config:
        orm_mode = True

# Schema per la risposta di tutti gli User
class Users(BaseModel):
    users: List[User]

# Schema per restituire una istanza di UserProfile
class UserProfile(BaseModel):
    id: int
    user_id: int
    profile_id: int
    motivation: Optional[str] = None

    class Config:
        orm_mode = True
        
# Schema per la risposta di tutti gli UserProfile
class UserProfiles(BaseModel):
    userprofiles: List[UserProfile]
    
    # Schema per creare una nuova istanza di ProfileSector
class ProfileSectorCreate(BaseModel):
    userprofile_id: int
    sector_id: int
    motivation: Optional[str] = None

# Schema per restituire una istanza di ProfileSector
class ProfileSector(BaseModel):
    id: int
    userprofile_id: int
    sector_id: int
    motivation: Optional[str] = None

    class Config:
        orm_mode = True

# Schema per creare una nuova istanza di SectorRole
class SectorRoleCreate(BaseModel):
    profilesector_id: int
    role_id: int
    motivation: Optional[str] = None

# Schema per restituire una istanza di SectorRole
class SectorRole(BaseModel):
    id: int
    profilesector_id: int
    role_id: int
    motivation: Optional[str] = None

    class Config:
        orm_mode = True

# Schema per creare una nuova istanza di RoleRoute
class RoleRouteCreate(BaseModel):
    sectorRole_id: int
    route_id: int
    motivation: Optional[str] = None

# Schema per restituire una istanza di RoleRoute
class RoleRoute(BaseModel):
    id: int
    sectorRole_id: int
    route_id: int
    motivation: Optional[str] = None

    class Config:
        orm_mode = True

# Schema per la risposta di tutti i ProfileSector
class ProfileSectors(BaseModel):
    profilesectors: List[ProfileSector]

# Schema per la risposta di tutti i SectorRole
class SectorRoles(BaseModel):
    sectoroles: List[SectorRole]

# Schema per la risposta di tutti i RoleRoute
class RoleRoutes(BaseModel):
    roleroutes: List[RoleRoute]
