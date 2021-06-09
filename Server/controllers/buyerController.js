require("dotenv").config();
const Buyer = require("../models/buyer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { buyerValidationSchema , loginValidationSchema } = require("./validations/validationSchema");
const { sendMail } = require("./validations/methods");

exports.buyerRegister = async (req, res, next) => {
  const { full_name, email, password, address, phone } = req.body;

  const { error } = buyerValidationSchema.validate(req.body)
  if (error) return res.status(400).send(error.details[0].message);

  const emailExist = await Buyer.findOne({ email: req.body.email });
  if (emailExist) return res.status(400).send("Email already exist");

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password , salt);

  const buyer = new Buyer({
    full_name : full_name,
    email : email,
    phone : phone,
    password : hashedPassword,
    address : address
  });

  try {
    const savedBuyer = await buyer.save();
    const token = jwt.sign({ email: email, password: hashedPassword },process.env.BUYER_TOKEN,{ expiresIn: "24h" });
    sendMail(token);
    res.send(savedBuyer);
  } catch (error) {
    res.status(400).send(error);
  }

};

exports.buyerLogin = async (req, res, next) => {

  const { error } = loginValidationSchema.validate(req.body)
  if (error) return res.status(400).send("error");

  const buyer = await Buyer.findOne({ email: req.body.email });
  if (!buyer) return res.status(400).send("Email  not found");

  const validPass = await bcrypt.compare(req.body.password, buyer.password);
  if (!validPass) return res.status(400).send("Invalid password");

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(buyer.password , salt);

  const token = jwt.sign({ _id: buyer._id, email: buyer.email, role :'buyer', password: hashedPassword, isValid:buyer.isValid},process.env.BUYER_TOKEN);
  res.header("auth-token", token).send(token);


};

exports.validBuyer = async (req, res, next) => {
  const token = req.params.token;
  const decodeToken = jwt.verify(token, process.env.BUYER_TOKEN);
  if (decodeToken) {
    const { email, password } = decodeToken;

    try {
      const findBuyer = await Buyer.findOne({ email });
      if (findBuyer) {
        bcrypt.compare(password, findBuyer.password, (err, result) => {
          if(!findBuyer.isValid)
            return res.status(400).send("cette compte pas validé")
          res.send("cette compte validé")
        });
      }
    } catch (error) {
      console.log("this is in error 1" + error);
    }
  } else {
    res.status(401).send("Ce lien est expiré");
  }
};

exports.getAllBuyers = async (req, res, next) => {
  try {
    const buyers = await Buyer.find();
    res.json(buyers);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.deleteBuyer = async (req, res, next) => {
  try {
    const Buyerdelete = await Buyer.deleteOne({
      _id: req.params.id,
    });
    res.status(201).send(Buyerdelete);
  } catch (error) {
    res.status(400).send({ message: error.message });
  }
};