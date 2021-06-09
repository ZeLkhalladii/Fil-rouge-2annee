const express = require("express");
require("dotenv").config();
const app = express();
const db = require("./config/configs");
const buyerRouter = require("./routes/buyerRouter");
const adminRouter = require("./routes/adminRouter");
const categoryRouter = require("./routes/categoryRouter");
const productRouter = require("./routes/productRouter");
const superAdminRouter = require("./routes/superAdminRouter");
const orderRouter = require("./routes/orderRouter");
const deliveryManRouter = require("./routes/deliveryManRouter");
const cors = require("cors");
app.use(express.json());

// config app
require('dotenv').config()

db.on("error", (err) => console.log(err));
db.once("open", () => console.log("connected to database"));

app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, auth-token"
  );
  res.header(
    "Access-Control-Allow-Methods",
    "GET, PATCH, POST, OPTIONS, PUT, DELETE"
  );
  next();
});

app.get('/', (req, res) => {
  res.send('OK')
})

app.use('/uploads', express.static('./uploads'));

app.use("/superAdmin", superAdminRouter);
app.use("/buyer", buyerRouter);
app.use("/admin", adminRouter);
app.use("/category", categoryRouter);
app.use("/product", productRouter);
app.use("/order", orderRouter);
app.use("/deliveryMan", deliveryManRouter);

app.use(cors())

app.listen(process.env.PORT, () => {
  console.log("connected to server " + process.env.PORT);
});
