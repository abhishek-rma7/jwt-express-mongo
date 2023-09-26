import jwt from "jsonwebtoken";
import { promisify } from "util";
import { Model } from "mongoose";

const auth = (Users, method) => async (req, res, next) => {
  let token = null;
  // Checking token from cookies
  if (method === "cookies") {
    if (req.cookies.jwt) {
      token = req.cookies.jwt;
    }
  } else if (method === "bearer") {
    if (
      req.headers.authorization &&
      req.headers.authorization.split(" ")[0] === "Bearer"
    ) {
      token = req.headers.authorization.split(" ")[1];
    }
  }

  if (!token) {
    return res
      .status(401)
      .json({ message: "You are not logged in! Please login to get access" });
  }

  // Decoding and verifying the token

  try {
    const decoded = await promisify(jwt.verify)(
      token,
      process.env.JWT_SECRET_KEY
    );

    if (!decoded) {
      return res.status(400).json({ message: "Invalid signature." });
    }
    const currentUser = await Users.findById(decoded.id);

    if (!currentUser) {
      return res.status(403).json({
        message: "The user belonging to the token no longer exists.",
      });
    }

    // Checking if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return res.status(403).json({
        message: "User recently changed password! Please login again",
      });
    }

    req.user = currentUser; // storing user to the req
    next();
  } catch (error) {
    return res
      .status(403)
      .json({ message: "Session expired. Please login again." });
  }
};

export default auth;

export const restrictTO =
  (...roles) =>
  (req, res, next) => {
    // roles--> ['admin', 'moderator', 'user]  if(role--> 'user') then no permission
    if (!roles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ message: "You do not have permission to perform this action" });
    }
    next();
  };
