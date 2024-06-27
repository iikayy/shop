from functools import wraps
from fastapi import FastAPI, Depends, HTTPException, status, Form, Path
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from forms import MenuItem, UpdateMenu, UpdateOrder, OrderItem, UserOut, Token, User, TokenData
from models import *
from passlib.context import CryptContext
from pydantic import EmailStr
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

# Secret key for JWT
SECRET_KEY = "YOUR_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI()

Base.metadata.create_all(bind=engine)

# Admin ID List
ADMIN_IDS = [1, 3]


# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Utility functions
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


def authenticate_user(db, email: str, password: str):
    user = get_user(db, email)
    if not user or not verify_password(password, user.password):
        return None
    return user


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = credentials.credentials
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


# Role-based access control decorators
def admin_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        current_user: User = kwargs.get('current_user')
        if current_user.id not in ADMIN_IDS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        return await func(*args, **kwargs)
    return wrapper


def user_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        current_user: User = kwargs.get('current_user')
        if current_user.id in ADMIN_IDS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User access required"
            )
        return await func(*args, **kwargs)
    return wrapper


@app.post("/register", response_model=UserOut)
async def register_user(
        email: EmailStr = Form(...),
        name: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(get_db)
):
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    hashed_password = get_password_hash(password)
    new_user = User(
        email=email,
        name=name,
        password=hashed_password,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/token", response_model=Token)
async def login_for_access_token(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = authenticate_user(db, email, password)
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


@app.get("/menu", response_model=list[MenuItem])
def get_all_menu(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    all_menu = db.query(Menu).all()
    return all_menu


@app.get("/search/{name}", response_model=MenuItem)
def search_menu(name: str = Path(description="The name of the food in the menu"),
                db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)
                ):
    name.food_name = name.food_name.title()
    result = db.query(Menu).filter(Menu.food_name == name).first()
    if not result:
        raise HTTPException(status_code=404, detail="Menu item not found")
    return result


@app.post("/add", response_model=MenuItem)
@admin_required
async def add_new_menu_item(menu_item: MenuItem, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    menu_item.food_name = menu_item.food_name.title()  # Ensure the food_name is in uppercase
    if menu_item.food_name.lower() == 'string' or str(menu_item.food_img_url).lower() == 'string':
        raise HTTPException(status_code=400, detail="Enter a valid input")
    if menu_item.food_price < 1 or menu_item.food_quantity < 1:
        raise HTTPException(status_code=400, detail="Price and quantity must be greater than 1")
    db_menu_item = db.query(Menu).filter(Menu.food_name == menu_item.food_name).first()
    if db_menu_item:
        raise HTTPException(status_code=400, detail="Menu item already exists")
    new_menu_item = Menu(**menu_item.dict())
    db.add(new_menu_item)
    db.commit()
    db.refresh(new_menu_item)
    return new_menu_item


@app.post("/new-order", response_model=dict)
async def create_order(order_item: OrderItem, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    order_item.food_name = order_item.food_name.title()  # Ensure the food_name is in uppercase
    db_menu_item = db.query(Menu).filter(Menu.food_name == order_item.food_name).first()
    if not db_menu_item:
        raise HTTPException(status_code=400, detail="Menu item not available")
    if order_item.food_name.lower() == 'string':
        raise HTTPException(status_code=400, detail="Enter a valid input")
    if order_item.quantity_ordered < 1:
        raise HTTPException(status_code=400, detail="Quantity must be greater than 1")
    new_order = Order(food_name=order_item.food_name.title(), quantity_ordered=order_item.quantity_ordered, user_id=current_user.id)
    db.add(new_order)
    db.commit()
    db.refresh(new_order)
    return {"Successfully created your order": f"order_id is {new_order.id}"}


@app.put("/update_menu/{food_name}", response_model=MenuItem)
@admin_required
async def update_menu(
    menu_update: UpdateMenu,
    food_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    menu_update.food_name = menu_update.food_name.title()  # Ensure the food_name is in uppercase
    menu = db.query(Menu).filter(Menu.food_name == menu_update.food_name).first()

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


@app.put("/update_order/{order_id}", response_model=dict)
def update_order(order_id: int, order_update: UpdateOrder, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order item not found")
    if order.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You're not allowed to update this order")
    for key, value in order_update.dict(exclude_unset=True).items():
        if key == "quantity_ordered" and value < 1:
            raise HTTPException(status_code=400, detail="Quantity must be greater than 1")
        if key == "food_name" and value.lower() == "string":
            raise HTTPException(status_code=400, detail="Enter a valid input")
        setattr(order, key, value)
    db.commit()
    db.refresh(order)
    return {"Successfully updated your order": f"order_id is {order_id}"}


@app.delete("/delete_menu/{food_name}", response_model=dict)
@admin_required
async def delete_menu_item(food_name: str = Path(description="Enter food_name"),
                           db: Session = Depends(get_db),
                           current_user: User = Depends(get_current_user)):
    food_name = food_name.title()  # Ensure the food_name is in uppercase
    menu_item = db.query(Menu).filter(Menu.food_name == food_name).first()
    if not menu_item:
        raise HTTPException(status_code=404, detail="Menu item not found")
    db.delete(menu_item)
    db.commit()
    return {"success": "Successfully deleted the menu item"}


@app.delete("/delete_order/{order_id}", response_model=dict)
def delete_order(order_id: int = Path(description="Enter order_id"),
                 db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order item not found")
    if order.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You're not allowed to delete this order")
    db.delete(order)
    db.commit()
    return {"success": "Successfully deleted the order"}


# # Route to logout user
# @app.post("/logout")
# async def logout_user():
#     response = JSONResponse(content={"message": "Successfully logged out"})
#     manager.set_cookie(response, "")
#     return response
