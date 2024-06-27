from pydantic import BaseModel, EmailStr


class MenuItem(BaseModel):
    food_name: str
    food_quantity: int
    food_price: float
    food_img_url: str


class OrderItem(BaseModel):
    food_name: str
    quantity_ordered: int


class UpdateMenu(BaseModel):
    food_name: str | None
    food_quantity: int | None
    food_price: float | None
    food_img_url: str | None


class UpdateOrder(BaseModel):
    food_name: str | None
    quantity_ordered: int | None


class User(BaseModel):
    email: EmailStr
    name: str
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    email: EmailStr
    name: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None
