from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ARRAY, text 
from sqlalchemy import Table, UniqueConstraint, PrimaryKeyConstraint, ForeignKey, Date


Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    name = Column(String(50), nullable=False)
    surname = Column(String(50), nullable=False)
    password = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    superuser = Column(Boolean, unique=False, nullable=False, default=False)
    #admin = Column(Boolean, unique=False, nullable=False, default=False)
    creator = Column(String(50), nullable=True)
    id_creator = Column(Integer, nullable=True)
    creation_date = Column(Date, nullable=True)
    active = Column(Boolean, unique=False, nullable=False, default=False)
    only_observer = Column(Boolean, nullable=True)
    defaultSector = Column(Integer, ForeignKey("sectors.id"))
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Profile(Base):
    __tablename__ = "profiles"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    name = Column(String(50), nullable=False)
    description = Column(String(200))
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Sector(Base):
    __tablename__ = "sectors"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    name = Column(String(50), nullable=False)
    description = Column(String(200))
    reserved = Column(Boolean, nullable=False, default=False)
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    name = Column(String(50), nullable=False)
    description = Column(String(200))
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Route(Base):
    __tablename__ = "routes"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    name = Column(String(50))
    path = Column(String(50), nullable=False)
    description = Column(String(100), nullable=False)
    active = Column(Boolean, nullable=False, default=True)  
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class UserProfile(Base):
    __tablename__ = "userprofiles"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    profile_id = Column(Integer, ForeignKey("profiles.id"))
    motivation = Column(String(200))
    __table_args__ = (UniqueConstraint('user_id', 'profile_id', name='uq_user_profile'),)
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ProfileSector(Base):
    __tablename__ = "profilesectors"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    motivation = Column(String(200))
    userprofile_id = Column(Integer, ForeignKey("userprofiles.id"))
    sector_id = Column(Integer, ForeignKey("sectors.id"))
    __table_args__ = (UniqueConstraint('userprofile_id', 'sector_id', name='uq_userprofile_sector'),)
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class SectorRole(Base):
    __tablename__ = "sectoroles"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    motivation = Column(String(200))
    profilesector_id = Column(Integer, ForeignKey("profilesectors.id"))
    role_id = Column(Integer, ForeignKey("roles.id"))
    __table_args__ = (UniqueConstraint('profilesector_id', 'role_id', name='uq_profilesector_role'),)
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class RoleRoute(Base):
    __tablename__ = "roleroutes"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    motivation = Column(String(200))
    sectorRole_id = Column(Integer, ForeignKey("sectoroles.id"))
    route_id = Column(Integer, ForeignKey("routes.id"))
    __table_args__ = (UniqueConstraint('sectorRole_id', 'route_id', name='uq_sectorole_route'),)
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
