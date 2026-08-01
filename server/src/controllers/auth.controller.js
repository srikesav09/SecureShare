import { registerUser } from "../services/auth.service.js";

export const register = async (req, res) => {
  const result = await registerUser(req.body);

  res.status(200).json(result);
};