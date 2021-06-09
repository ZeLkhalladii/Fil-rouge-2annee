require("dotenv").config();
const Order = require("../models/order");
const jwt = require("jsonwebtoken");

exports.addOrder = async (req, res, next) => {
  const token = req.header("auth-token");
  const id_buyer = jwt.verify(token, process.env.BUYER_TOKEN)._id;

  const newOrder = new Order({
    id_product: req.body.id_product,
    id_seller: req.body.id_seller,
    id_buyer: req.body.id_buyer,
    totalPrice: totalPrice,
    address: req.body.address
  });
  try {
    const order = await newOrder.save();
    res.status(201).send(order);
  } catch (error) {
    res.status(400).send({ message: error.message });
  }
};
exports.getAllOrders = async (req, res, next) => {
  try {
    const orders = await Order.find();
    res.status(200).send(orders);
  } catch (error) {
    res.status(404).send({ message: error.message });
  }
};


exports.getOrder = async (req, res, next) => {
  try {
    const order = await Order.findOne({ _id: req.params.id });
    res.status(201).send(order);
  } catch (error) {
    res.status(400).send({ message: error.message });
  }
};
