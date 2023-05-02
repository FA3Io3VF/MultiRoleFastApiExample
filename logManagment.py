from loguru import logger
from fastapi import Request
from fastapi.responses import JSONResponse
from getpass import getpass
from fastapi import HTTPException, Depends

"""
TODO: Create a LogManager class to handle HTTPExceptions and Log in a centralized way
      Save errors and logs on a table
"""
logger.add("file.log", format="<level> {level: <8} </level> \
    | {time:DD-MM-YYYY HH:mm} | {file}:{line} - {function}() | {message}")

