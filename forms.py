from pydantic import BaseModel, EmailStr
from typing import Optional


class MenuItem(BaseModel):
    food_name: str
    food_quantity: int
    food_price: float
    food_img_url: str


class OrderItem(BaseModel):
    food_name: str
    quantity_ordered: int


class UpdateMenu(BaseModel):
    food_name: Optional[str]
    food_quantity: Optional[int]
    food_price: Optional[float]
    food_img_url: Optional[str]


class UpdateOrder(BaseModel):
    food_name: Optional[str]
    quantity_ordered: Optional[int]


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
    username: Optional[str]
