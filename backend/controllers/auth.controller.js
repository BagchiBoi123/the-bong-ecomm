import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { sendWelcomeEmail } from "../emails/emailHandlers.js";

export const signup = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const userExists = await User.findOne({ email });

    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    // const user = await User.create({ name, email, password });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = new User({ name, email, password: hashedPassword });

    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "3d",
    });

    res.cookie("jwt-token", token, {
      httpOnly: true, //prevents XSS attacks
      maxAge: 3 * 24 * 60 * 60 * 1000,
      sameSite: "strict", // prevents CSRF attacks
      secure: process.env.NODE_ENV === "production", // prevents man-in-the-middle attacks
    });

    res.status(201).json({ user, message: "User created successfully" });

    const profileUrl = process.env.CLIENT_URL + "/profile/" + user.name;

    // Send emails on successful registration
    // try {
    //   await sendWelcomeEmail(user.email, user.name, profileUrl);
    // } catch (emailError) {
    //   console.error("Error sending welcome email", emailError);
    // }
  } catch (error) {
    console.log("Error in signup: ", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User doesn't exists" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "3d",
    });

    res.cookie("jwt-token", token, {
      httpOnly: true, //prevents XSS attacks
      maxAge: 3 * 24 * 60 * 60 * 1000,
      sameSite: "strict", // prevents CSRF attacks
      secure: process.env.NODE_ENV === "production", // prevents man-in-the-middle attacks
    });

    res.json({ message: "Logged in successfully" });
  } catch (error) {
    console.log("Error in login: ", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const logout = async (req, res) => {
  res.clearCookie("jwt-token");
  res.json({ message: "Logged out successfully" });
};
