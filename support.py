import socket
from datetime import datetime
    
def isConnected() -> bool:
    IPaddress = socket.gethostbyname(socket.gethostname())
    return not IPaddress == socket.INADDR_LOOPBACK or "127.0.0.1"

def getNow():
    now = datetime.now()
    return now.strftime("%d/%m/%Y %H:%M:%S")
