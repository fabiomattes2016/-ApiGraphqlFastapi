import ldap
import jwt

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware



def ldap_authenticate(username: str, password: str):
    # Configuração do LDAP
    LDAP_SERVER = 'ldaps://sicredi.net.br:636'
    BASE_DN = f"CN={username},CN=UsersSicredi,DC=sicredi,DC=net,DC=br"
    search_filter = f"(&(objectClass=person)(sAMAccountName={username}))"
    
    try:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        ldap_conn = ldap.initialize(LDAP_SERVER, trace_level=None)
        ldap_conn.protocol_version = ldap.VERSION3
        ldap_conn.simple_bind_s(f"{BASE_DN}", password)
        result = ldap_conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, search_filter, ['*'])
        ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
        ldap_conn.unbind_s()
        
        if result:
            user_info = result[0][1]
            id = user_info.get('employeeID', [''])[0].decode('utf-8').replace('/1/', '')
            first_name = user_info.get('givenName', [''])[0].decode('utf-8')
            last_name = user_info.get('sn', [''])[0].decode('utf-8')
            email = user_info.get('mail', [''])[0].decode('utf-8')
            title = user_info.get('title', [''])[0].decode('utf-8')
            company = user_info.get('company', [''])[0].decode('utf-8')
            active = user_info.get('sicrediAccountStatus', [''])[0].decode('utf-8')
        
        return id, first_name, last_name, email, title, company, active, True
    except ldap.INVALID_CREDENTIALS:
        return False
    
    

# Configuração JWT
SECRET_KEY = "parangaricutirrimiruaro"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_MINUTES = 30


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


# Configuração do FastAPI e GraphQL
app = FastAPI()

origins = [
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/graphql")
def graphql_endpoint(query: str):
    transport = RequestsHTTPTransport(url="http://localhost:8000/graphql", use_json=True)
    client = Client(transport=transport, fetch_schema_from_transport=True)
    result = client.execute(gql(query))
    
    return result


# Endpoint de Login
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth")

@app.post("/auth")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    
    id, first_name, last_name, email, title, company, active, authenticated = ldap_authenticate(username, password)
    
    if not authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário e/ou senha incorretos!",
            headers={"WWW-Authenticate": "Bearer"},
        )
    elif active != 'ACTIVE':
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário desativado, entre em contato com o suporte!",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token = create_access_token(
        {
            "sub": username,
            "iss": "Sicredi",
            "name": first_name + " " + last_name,
            "email": email,
            "role": title,
            "aud": "AppDeTestes",
        }
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "user": {
            "username": username,
            "full_name": first_name + " " + last_name, 
            "email": email, 
            "role": title,
        },
    }


@app.get("/token/verify")
async def token_verify(token: str):
    try:
        decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_aud": "true", "verify_iss": "true"}, audience="AppDeTestes", issuer="Sicredi")
        return decoded_payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado!",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido!",
            headers={"WWW-Authenticate": "Bearer"},
        )
