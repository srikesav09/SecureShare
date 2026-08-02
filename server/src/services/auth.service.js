import bcrypt from "bcrypt";

import User from "../models/user.model.js";

export const registerUser = async (userData) => {

  const {name, email, password} = userData;
  const existingUser = await User.findOne({email});
  if(existingUser) {
    throw new Error("Email already exists");
  }
  const hashedPassword = await bcrypt.hash(password,10);
  const user = await User.create({
    name,
    email,
    password: hashedPassword,
  });

  return {
    success: true,
    message: "User registered successfully",
    data: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
    },
  };
};
