require("dotenv").config();
const Product = require("../models/product");
const jwt = require("jsonwebtoken");

exports.addProduct = async (req, res, next) => {
    const newProduct = new Product({
      name: req.body.name,
      description: req.body.description,
      id_category: req.body.id_category,
      price: req.body.price,
      picture: req.files[0].filename
    });

  try {
    const savedProduct = await newProduct.save();
    res.send(savedProduct);
  } catch (error) {
    res.status(400).send(error);
  }
  };

exports.getAllProducts = async (req, res, next) => {
  try {
    const products = await Product.find();
    res.status(200).send(products);
  } catch (error) {
    res.status(404).send({ message: error.message });
  }
};

exports.updateProduct = async (req, res, next) => {
  const token = req.header("auth-token");
  const id_seller = jwt.verify(token, process.env.SELLER_TOKEN)._id;
  var pictures = [];
  for (let i = 0; i < req.files.length; i++) {
    pictures.push(req.files[i].filename);
  }
  const product = await Products.findById({ _id: req.params.id });

  if (!product) {
    res.status(404).send({ message: "Product not found" });
  }

  product.name = req.body.name;
  product.price = req.body.price;
  product.description = req.body.description;
  product.picture = pictures;
  product.id_seller = id_seller;
  product.id_category = req.body.id_category;

  try {
    const updatedProduct = await product.save();
    res.status(201).send(updatedProduct);
  } catch (error) {
    res.status(400).send({ message: error.message });
  }
};

exports.deleteProduct = async (req, res, next) => {
  const token = req.header("auth-token");

  const seller = await Seller.findOne({ _id: id_seller });
  seller.productsCount -= 1;
  try {
    const deletedProduct = await Product.deleteOne({ _id: req.params.id });
    const updatedSeller = await seller.save();
    res.status(201).send(deletedProduct);
  } catch (error) {
    res.status(400).send({ message: error.message });
  }
};

exports.getProduct = async (req, res, next) => {
  try {
    const product = await Product.findOne({ _id: req.params.id });
    res.status(201).send(product);
  } catch (error) {
    res.status(400).send({ message: error.message });
  }
};
exports.getProductsByUserId = async (req, res, next) => {
  try {
    const products = await Product.find({ id_seller: req.params.id });
    res.status(201).send(products);
  } catch (error) {
    res.status(400).send({ message: error.message });
  }
};
