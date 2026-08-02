import { registerUser } from "../services/auth.service.js";

export const register = async (req, res) => {
  try {
    const result = await registerUser(req.body);

  res.status(200).json(result);
  }catch (error){
    return res.status(400).json({

        success:false,

        message:error.message

    });
  }
};