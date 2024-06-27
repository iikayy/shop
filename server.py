from fastapi import FastAPI, Depends, HTTPException, Path, Form, status
from database import SessionLocal, engine
from sqlalchemy.orm import Session
from forms import MenuItem, UpdateMenu, UpdateOrder, OrderItem, UserOut, Token, User, TokenData
from models import *
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import EmailStr
import secrets
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import logging


logging.basicConfig(level=logging.DEBUG)


# Secret key for JWT
SECRET_KEY = secrets.token_hex(32)
SECRET = SECRET_KEY

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 30

# manager = LoginManager(SECRET, token_url='/login', use_cookie=True)
# manager.cookie_name = "auth"

# Initialize password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

Base.metadata.create_all(bind=engine)


# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


#  Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user(db, email: str):
    return db.query(User).filter(User.email == email).first()


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, email=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: get_user = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# Route to register a new user
@app.post("/register", response_model=UserOut)
async def register_user(
        email: EmailStr = Form(...),
        name: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(get_db)
):
    # Check if user already exists
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Hash the password
    hashed_password = pwd_context.hash(password)

    # Create new user
    new_user = User(
        email=email,
        name=name,
        password=hashed_password,
    )

    # Add user to the database
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# Route to get all menu items
@app.get("/menu", response_model=list[MenuItem])
def get_all_menu(db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)
                 ):
    all_menu = db.query(Menu).all()
    return all_menu


# Route to search for a particular menu item
@app.get("/search/{name}", response_model=MenuItem)
def search_menu(name: str = Path(description="The name of the food in the menu"),
                db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)
                ):
    result = db.query(Menu).filter(Menu.food_name == name.title()).first()
    if not result:
        raise HTTPException(status_code=404, detail="Menu item not found")
    return result


# Route to add a new menu item
@app.post("/add", response_model=MenuItem)
def add_new_menu_item(menu_item: MenuItem, db: Session = Depends(get_db),current_user: User = Depends(get_current_user) ):
    if menu_item.food_name.lower() == 'string' or str(menu_item.food_img_url).lower() == 'string':
        raise HTTPException(status_code=400, detail="Enter a valid input")
    if menu_item.food_price < 1 or menu_item.food_quantity < 1:
        raise HTTPException(status_code=400, detail="Price and quantity must be greater than 1")
    db_menu_item = db.query(Menu).filter(Menu.food_name == menu_item.food_name.title()).first()
    if db_menu_item:
        raise HTTPException(status_code=400, detail="Menu item already exists")
    new_menu_item = Menu(**menu_item.dict())
    db.add(new_menu_item)
    db.commit()
    db.refresh(new_menu_item)
    return new_menu_item


# Route to make a new order
@app.post("/new-order", response_model=OrderItem)
async def create_order(order_item: OrderItem, db: Session = Depends(get_db),
                       current_user: User = Depends(get_current_user)):
    db_menu_item = db.query(Menu).filter(Menu.food_name == order_item.food_name.title()).first()
    if not db_menu_item:
        raise HTTPException(status_code=400, detail="Menu item not available")
    if order_item.food_name.lower() == 'string':
        raise HTTPException(status_code=400, detail="Enter a valid input")
    if order_item.quantity_ordered < 1:
        raise HTTPException(status_code=400, detail="Quantity must be greater than 1")
    new_order = Order(**order_item.dict())
    db.add(new_order)
    db.commit()
    db.refresh(new_order)
    return new_order


# Route to update the menu
@app.put("/update_menu/{food_name}", response_model=MenuItem)
def update_menu(
    menu_update: UpdateMenu,
    food_name: str = Path(description="The name of the food you want to update in the menu"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    menu = db.query(Menu).filter(Menu.food_name == food_name.title()).first()
    if not menu:
        raise HTTPException(status_code=404, detail="Menu item not found")
    for key, value in menu_update.dict(exclude_unset=True).items():
        if key == "food_price" and value < 1:
            raise HTTPException(status_code=400, detail="Price must be greater than 1")
        if key == "food_name" and value.lower() == "string":
            raise HTTPException(status_code=400, detail="Enter a valid input")
        if key == "food_img_url" and value.lower() == "string":
            raise HTTPException(status_code=400, detail="Enter a valid input")
        if key == "food_quantity" and value < 1:
            raise HTTPException(status_code=400, detail="Quantity must be greater than 1")
        setattr(menu, key, value)
    db.commit()
    db.refresh(menu)
    return menu


# Route to update an order
@app.put("/update_order/{food_name}", response_model=OrderItem)
def update_order(food_name: str, order_update: UpdateOrder,
                 db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    order = db.query(Order).filter(Order.food_name == food_name.lower()).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order item not found")
    for key, value in order_update.dict(exclude_unset=True).items():
        if key == "quantity_ordered" and value < 1:
            raise HTTPException(status_code=400, detail="Quantity must be greater than 1")
        if key == "food_name" and value.lower() == "string":
            raise HTTPException(status_code=400, detail="Enter a valid input")
        setattr(order, key, value)
    db.commit()
    db.refresh(order)
    return order


# Route to delete a menu item
@app.delete("/delete_menu/{food_name}", response_model=dict)
def delete_menu_item(food_name: str = Path(description="The name of the food you want to delete from the menu"),
                     db: Session = Depends(get_db),
                     current_user: User = Depends(get_current_user)):
    menu_item = db.query(Menu).filter(Menu.food_name == food_name.title()).first()
    if not menu_item:
        raise HTTPException(status_code=404, detail="Menu item not found")
    db.delete(menu_item)
    db.commit()
    return {"success": "Successfully deleted the menu item"}


# Route to delete an order
@app.delete("/delete_order/{order_name}", response_model=dict)
def delete_order(order_name: str = Path(description="The name of the food you want to delete from your order"),
                 db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    order = db.query(Order).filter(Order.food_name == order_name.lower()).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order item not found")
    db.delete(order)
    db.commit()
    return {"success": "Successfully deleted the order"}


my_key = {
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpaV9rYXl5QHlhaG9vLmNvbSIsImV4cCI6MTcxNzc3MTI2OH0.8dsgMzsUddbqZIbTuJN985p1vKGFMJ5yQHfA5GAXtw0",
  "token_type": "bearer"
}
