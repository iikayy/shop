from sqlalchemy import Column, ForeignKey, Integer, String, Float
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(250), unique=True, index=True)
    password = Column(String(250))
    name = Column(String(250))
    orders = relationship("Order", back_populates="user", cascade="all, delete-orphan")


class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="orders")
    menu_items = relationship("Menu", secondary="order_menu", back_populates="orders")
    food_name = Column(String(250))
    quantity_ordered = Column(Integer)


class Menu(Base):
    __tablename__ = "menu"
    id = Column(Integer, primary_key=True, index=True)
    food_name = Column(String(250), unique=True)
    food_quantity = Column(Integer)
    food_price = Column(Float)
    food_img_url = Column(String)
    orders = relationship("Order", secondary="order_menu", back_populates="menu_items")


class OrderMenu(Base):
    __tablename__ = "order_menu"
    order_id = Column(Integer, ForeignKey("orders.id"), primary_key=True)
    menu_id = Column(Integer, ForeignKey("menu.id"), primary_key=True)


