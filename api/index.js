const express = require("express")
const app = express();
const cors = require('cors');
const mongoose = require("mongoose")
const dotenv = require("dotenv")
const userRoute = require("./routes/user")
const authRoute = require("./routes/auth")
const productRoute = require("./routes/product")
const cartRoute = require("./routes/cart")
const orderRoute = require("./routes/order")

app.use(cors());

dotenv.config();
mongoose
    .connect(process.env.MONGO_URL)
    .then(()=> console.log("DBConnection Successfull!"))
    .catch((err) => {
        console.log(err);
    });

app.use(express.json());
app.use("/api/users", userRoute);
app.use("/api/auth", authRoute);
app.use("/api/products", productRoute);
app.use("/api/carts", cartRoute);
app.use("/api/orders", orderRoute);


app.listen(process.env.PORT || 5000 , ()=>{
    console.log("backend server running "+process.env.PORT )
})