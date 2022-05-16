const express = require('express');
const app = express();
const jwt = require("jsonwebtoken");
const cors = require("cors");
let refreshTokens = [];

app.use(express.json());
app.use(cors());

app.post("/refresh", (req, res, next) => {
  const refreshToken = req.body.token;
  if(!refreshToken || !refreshTokens.includes(refreshToken)) {
    return res.status(403).json({ message: "Refresh token not found, login again" });
  }

  // If the refresh token is valid, create a new accessToken and return it.
  jwt.verify(refreshToken, "refresh", (err, user) => {
    if(!err) {
      const accessToken =jwt.sign({ username: user.name }, "access", { 
        expiresIn: "20s" 
      });
      return res.status(201).json({ success: true, accessToken });
    } else {
      return res.status(403).json({ 
        success: false,
        message: "Invalid refresh token"
      });
    }
  });
});

// Middleware to authenticate user by verifying his/her jwt-token.
function auth(req, res, next) {
  let token = req.headers["authorization"];
  token = token.split(" ")[1]; // access token
  console.log("token = ", token);

  jwt.verify(token, "access", (err, user) => {
    if(!err) {
      req.user = user;
      next();
    } else if (err.message === "jwt expired") {
      return res.json({
          success: false,
          message: "Access token expired"
      });
    } else {
      return res.status(403).json({ message: "User not authenticated" });
    }
  });
}

app.post("/protected", auth, (req, res) => {
  res.send("Inside protected route");
});

app.post("/login", (req, res) => {
  const user = req.body.user;

  if (!user) {
    return res.status(404).json({ message: "Body Empty" });
  }

  let accessToken = jwt.sign(user, "access", { expiresIn: "20s" });
  let refreshToken = jwt.sign(user, "refresh", { expiresIn: "7d" });
  refreshTokens.push(refreshToken);

  return res.status(201).json({
    accessToken,
    refreshToken,
  });

});

app.listen(3000);