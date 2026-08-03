import { registerUser,loginUser, getProfile} from "../services/auth.service.js";

import { asyncHandler } from "../utils/asyncHandler.js";

export const register = asyncHandler(async (req, res) => {
  const result = await registerUser(req.body);

  return res.status(201).json(result);
});

export const login = asyncHandler(async(req,res)=>{
        const result = await loginUser(req.body);
        return res
            .status(200)
            .json(result);
});

export const profile = asyncHandler(async(req,res)=>{
  const result = await getProfile(req.user.id);

  return res.status(200).json(result);
})

